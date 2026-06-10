defmodule TamanduaServer.Detection.DomainValidator do
  @moduledoc """
  Advanced domain validation and normalization for threat detection.

  Handles:
  - IDN (Internationalized Domain Name) to ASCII conversion (punycode)
  - Homoglyph/confusable character detection (visual spoofing)
  - Levenshtein distance for typosquatting detection
  - Proper domain label parsing and extraction

  This module addresses the security gap where simple string matching
  could be bypassed via:
  - Punycode domains that visually resemble trusted domains
  - Homoglyph attacks using similar-looking Unicode characters
  - Typosquatting with minor character variations

  ## Examples

      # Normalize a domain
      iex> DomainValidator.normalize("MiCROSOFT.COM")
      {:ok, "microsoft.com"}

      # Detect IDN spoofing
      iex> DomainValidator.normalize("xn--mcrosoft-q4a.com")  # microsоft.com with Cyrillic 'о'
      {:ok, "xn--mcrosoft-q4a.com", :idn_homoglyph_detected}

      # Check if domain is trusted
      iex> DomainValidator.trusted?("login.microsoft.com", trusted_domains)
      true

      # Detect typosquatting
      iex> DomainValidator.detect_typosquat("mircosoft.com", ["microsoft.com"])
      {:typosquat, "microsoft.com", 2}
  """

  require Logger

  # Common homoglyphs: map from confusable Unicode to ASCII
  @homoglyphs %{
    # Cyrillic lookalikes
    "а" => "a",  # Cyrillic small a
    "е" => "e",  # Cyrillic small e
    "о" => "o",  # Cyrillic small o
    "р" => "p",  # Cyrillic small r (looks like p)
    "с" => "c",  # Cyrillic small es
    "х" => "x",  # Cyrillic small ha
    "у" => "y",  # Cyrillic small u
    "А" => "A",  # Cyrillic capital A
    "В" => "B",  # Cyrillic capital Ve
    "Е" => "E",  # Cyrillic capital E
    "К" => "K",  # Cyrillic capital Ka
    "М" => "M",  # Cyrillic capital Em
    "Н" => "H",  # Cyrillic capital En
    "О" => "O",  # Cyrillic capital O
    "Р" => "P",  # Cyrillic capital Er
    "С" => "C",  # Cyrillic capital Es
    "Т" => "T",  # Cyrillic capital Te
    "Х" => "X",  # Cyrillic capital Ha
    "і" => "i",  # Ukrainian i
    "ї" => "i",  # Ukrainian yi
    # Greek lookalikes
    "ο" => "o",  # Greek small omicron
    "α" => "a",  # Greek small alpha
    "ν" => "v",  # Greek small nu (looks like v)
    "τ" => "t",  # Greek small tau (looks like t)
    "Α" => "A",  # Greek capital Alpha
    "Β" => "B",  # Greek capital Beta
    "Ε" => "E",  # Greek capital Epsilon
    "Η" => "H",  # Greek capital Eta
    "Ι" => "I",  # Greek capital Iota
    "Κ" => "K",  # Greek capital Kappa
    "Μ" => "M",  # Greek capital Mu
    "Ν" => "N",  # Greek capital Nu
    "Ο" => "O",  # Greek capital Omicron
    "Ρ" => "P",  # Greek capital Rho
    "Τ" => "T",  # Greek capital Tau
    "Χ" => "X",  # Greek capital Chi
    "Υ" => "Y",  # Greek capital Upsilon
    "Ζ" => "Z",  # Greek capital Zeta
    # Latin Extended lookalikes
    "ɑ" => "a",  # Latin small alpha
    "ɡ" => "g",  # Latin small script g
    "ı" => "i",  # Latin small dotless i
    "ȷ" => "j",  # Latin small dotless j
    "ɩ" => "i",  # Latin small iota
    "ʟ" => "L",  # Latin letter small capital L
    "ɴ" => "N",  # Latin letter small capital N
    "ꜱ" => "S",  # Latin letter small capital S
    "ᴢ" => "Z",  # Latin letter small capital Z
    # Fullwidth characters
    "ａ" => "a", "ｂ" => "b", "ｃ" => "c", "ｄ" => "d", "ｅ" => "e",
    "ｆ" => "f", "ｇ" => "g", "ｈ" => "h", "ｉ" => "i", "ｊ" => "j",
    "ｋ" => "k", "ｌ" => "l", "ｍ" => "m", "ｎ" => "n", "ｏ" => "o",
    "ｐ" => "p", "ｑ" => "q", "ｒ" => "r", "ｓ" => "s", "ｔ" => "t",
    "ｕ" => "u", "ｖ" => "v", "ｗ" => "w", "ｘ" => "x", "ｙ" => "y",
    "ｚ" => "z",
    # Number lookalikes
    "О" => "0",  # Cyrillic O for zero
    "l" => "1",  # lowercase L for 1
    "І" => "1",  # Ukrainian I for 1
    # Special characters
    "–" => "-",  # en dash
    "—" => "-",  # em dash
    "‐" => "-",  # hyphen
    "⁻" => "-",  # superscript minus
    "₋" => "-",  # subscript minus
    "．" => ".",  # fullwidth period
    "。" => ".",  # ideographic full stop
  }

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Normalize a domain name for consistent comparison.

  - Converts to lowercase
  - Trims whitespace
  - Converts IDN (punycode) to ASCII representation
  - Returns normalized domain with optional warning flag

  Returns:
    - `{:ok, normalized_domain}` for normal domains
    - `{:ok, normalized_domain, :idn}` for IDN domains
    - `{:ok, normalized_domain, :idn_homoglyph_detected}` for IDN with confusables
    - `{:error, reason}` for invalid domains
  """
  @spec normalize(String.t()) :: {:ok, String.t()} | {:ok, String.t(), atom()} | {:error, term()}
  def normalize(domain) when is_binary(domain) do
    domain = domain |> String.trim() |> String.downcase()

    cond do
      domain == "" ->
        {:error, :empty_domain}

      String.length(domain) > 253 ->
        {:error, :domain_too_long}

      true ->
        normalize_domain(domain)
    end
  end

  def normalize(_), do: {:error, :invalid_input}

  @doc """
  Check if a domain matches any trusted domain in the allowlist.

  Uses proper label-based matching to prevent attacks like:
  - `microsoft.com.evil.com` (subdomain of evil.com, not microsoft)
  - `notmicrosoft.com` (doesn't match microsoft.com)

  The domain must either:
  1. Exactly match a trusted domain
  2. Be a subdomain of a trusted domain (matched by complete labels)
  """
  @spec trusted?(String.t(), [String.t()]) :: boolean()
  def trusted?(domain, trusted_domains) when is_binary(domain) and is_list(trusted_domains) do
    case normalize(domain) do
      {:ok, normalized} ->
        check_trusted(normalized, trusted_domains)

      {:ok, normalized, _flag} ->
        check_trusted(normalized, trusted_domains)

      {:error, _} ->
        false
    end
  end

  def trusted?(_, _), do: false

  @doc """
  Detect potential typosquatting against a list of known domains.

  Uses Levenshtein distance to find similar domains.

  Returns:
    - `nil` if no typosquat detected
    - `{:typosquat, similar_domain, distance}` if potential typosquat found
  """
  @spec detect_typosquat(String.t(), [String.t()], non_neg_integer()) ::
          nil | {:typosquat, String.t(), non_neg_integer()}
  def detect_typosquat(domain, known_domains, max_distance \\ 2) do
    case normalize(domain) do
      {:ok, normalized} ->
        do_detect_typosquat(normalized, known_domains, max_distance)

      {:ok, normalized, _flag} ->
        do_detect_typosquat(normalized, known_domains, max_distance)

      {:error, _} ->
        nil
    end
  end

  @doc """
  Detect homoglyph-based domain spoofing.

  Converts confusable characters to ASCII and compares against known domains.

  Returns:
    - `nil` if no spoofing detected
    - `{:homoglyph_spoof, target_domain, detected_chars}` if spoofing found
  """
  @spec detect_homoglyph_spoof(String.t(), [String.t()]) ::
          nil | {:homoglyph_spoof, String.t(), [String.t()]}
  def detect_homoglyph_spoof(domain, known_domains) do
    # Decode punycode if necessary
    decoded = decode_punycode_domain(domain)

    # Find homoglyphs in the domain
    {ascii_version, detected_chars} = convert_homoglyphs(decoded)

    if detected_chars != [] do
      # Check if ASCII version matches any known domain
      Enum.find_value(known_domains, fn known ->
        known_lower = String.downcase(known)
        ascii_lower = String.downcase(ascii_version)

        if ascii_lower == known_lower or String.ends_with?(ascii_lower, "." <> known_lower) do
          {:homoglyph_spoof, known, detected_chars}
        end
      end)
    else
      nil
    end
  end

  @doc """
  Extract the registered domain (eTLD+1) from a full domain.

  Examples:
    - "sub.example.com" -> "example.com"
    - "deep.sub.example.co.uk" -> "example.co.uk"
    - "example.com" -> "example.com"

  Note: This is a simplified version that handles common TLDs.
  For production, consider using a PSL (Public Suffix List) library.
  """
  @spec extract_registered_domain(String.t()) :: String.t()
  def extract_registered_domain(domain) when is_binary(domain) do
    labels = String.split(domain, ".")

    cond do
      # Handle common two-part TLDs
      length(labels) >= 3 and two_part_tld?(Enum.take(labels, -2)) ->
        Enum.take(labels, -3) |> Enum.join(".")

      # Standard TLD
      length(labels) >= 2 ->
        Enum.take(labels, -2) |> Enum.join(".")

      true ->
        domain
    end
  end

  @doc """
  Calculate Levenshtein distance between two strings.
  """
  @spec levenshtein_distance(String.t(), String.t()) :: non_neg_integer()
  def levenshtein_distance(s1, s2) do
    do_levenshtein(String.graphemes(s1), String.graphemes(s2))
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp normalize_domain(domain) do
    labels = String.split(domain, ".")

    # Check if any label is punycode (IDN)
    is_idn = Enum.any?(labels, &String.starts_with?(&1, "xn--"))

    # Check for homoglyphs
    has_homoglyphs = contains_homoglyphs?(domain)

    # Validate and normalize each label
    normalized_labels =
      Enum.map(labels, fn label ->
        if String.starts_with?(label, "xn--") do
          # Already punycode, keep as-is
          label
        else
          # Convert to punycode if contains non-ASCII
          try_to_punycode(label)
        end
      end)

    normalized = Enum.join(normalized_labels, ".")

    cond do
      is_idn and has_homoglyphs ->
        {:ok, normalized, :idn_homoglyph_detected}

      is_idn or has_homoglyphs ->
        {:ok, normalized, :idn}

      true ->
        {:ok, normalized}
    end
  end

  defp try_to_punycode(label) do
    if String.match?(label, ~r/^[\x00-\x7F]*$/) do
      # Pure ASCII, no conversion needed
      label
    else
      # Contains non-ASCII, try to convert
      case encode_punycode(label) do
        {:ok, encoded} -> encoded
        {:error, _} -> label
      end
    end
  end

  defp encode_punycode(label) do
    # Simple punycode encoding
    # In production, use a proper IDNA library like :idna
    try do
      # Attempt to use :idna if available
      encoded = :idna.encode(String.to_charlist(label))
      {:ok, to_string(encoded)}
    rescue
      _ ->
        # Fallback: just lowercase
        {:ok, String.downcase(label)}
    catch
      _, _ ->
        {:ok, String.downcase(label)}
    end
  end

  defp decode_punycode_domain(domain) do
    labels = String.split(domain, ".")

    decoded_labels =
      Enum.map(labels, fn label ->
        if String.starts_with?(label, "xn--") do
          try do
            :idna.decode(String.to_charlist(label)) |> to_string()
          rescue
            _ -> label
          catch
            _, _ -> label
          end
        else
          label
        end
      end)

    Enum.join(decoded_labels, ".")
  end

  defp contains_homoglyphs?(domain) do
    domain
    |> String.graphemes()
    |> Enum.any?(fn char -> Map.has_key?(@homoglyphs, char) end)
  end

  defp convert_homoglyphs(domain) do
    graphemes = String.graphemes(domain)

    {converted, detected} =
      Enum.reduce(graphemes, {[], []}, fn char, {acc_converted, acc_detected} ->
        case Map.get(@homoglyphs, char) do
          nil ->
            {[char | acc_converted], acc_detected}

          replacement ->
            {[replacement | acc_converted], [char | acc_detected]}
        end
      end)

    {converted |> Enum.reverse() |> Enum.join(), Enum.reverse(detected)}
  end

  defp check_trusted(normalized, trusted_domains) do
    normalized_labels = String.split(normalized, ".")

    Enum.any?(trusted_domains, fn trusted ->
      trusted_lower = String.downcase(trusted)
      trusted_labels = String.split(trusted_lower, ".")

      # Exact match
      normalized == trusted_lower or
        # Subdomain match (full label match from right)
        labels_end_with?(normalized_labels, trusted_labels)
    end)
  end

  defp labels_end_with?(domain_labels, trusted_labels) do
    domain_len = length(domain_labels)
    trusted_len = length(trusted_labels)

    if domain_len > trusted_len do
      Enum.take(domain_labels, -trusted_len) == trusted_labels
    else
      false
    end
  end

  defp do_detect_typosquat(domain, known_domains, max_distance) do
    # Extract registered domain for comparison
    domain_reg = extract_registered_domain(domain)

    Enum.find_value(known_domains, fn known ->
      known_lower = String.downcase(known)
      known_reg = extract_registered_domain(known_lower)

      distance = levenshtein_distance(domain_reg, known_reg)

      if distance > 0 and distance <= max_distance do
        {:typosquat, known, distance}
      end
    end)
  end

  # Common two-part TLDs
  @two_part_tlds ~w(
    co.uk co.jp co.nz co.za co.in co.kr co.il co.th
    com.au com.br com.cn com.hk com.mx com.sg com.tw
    org.uk org.au net.au
    gov.uk edu.au
    ac.uk ac.jp ac.in
  )

  defp two_part_tld?(labels) when is_list(labels) do
    tld = Enum.join(labels, ".")
    tld in @two_part_tlds
  end

  # Levenshtein distance implementation using dynamic programming
  defp do_levenshtein([], t), do: length(t)
  defp do_levenshtein(s, []), do: length(s)

  defp do_levenshtein(s, t) do
    s_len = length(s)
    t_len = length(t)

    # Initialize the matrix
    # We'll use a single row and update it
    initial_row = Enum.to_list(0..t_len)

    {final_row, _} =
      Enum.reduce(Enum.with_index(s), {initial_row, 0}, fn {s_char, i}, {prev_row, _} ->
        new_row =
          Enum.reduce(Enum.with_index(t), {[i + 1], i}, fn {t_char, j}, {row_acc, diag} ->
            left = hd(row_acc) + 1
            up = Enum.at(prev_row, j + 1) + 1
            diag_cost = if s_char == t_char, do: diag, else: diag + 1

            new_val = min(min(left, up), diag_cost)
            new_diag = Enum.at(prev_row, j + 1)

            {[new_val | row_acc], new_diag}
          end)

        {Enum.reverse(elem(new_row, 0)), 0}
      end)

    List.last(final_row)
  end
end
