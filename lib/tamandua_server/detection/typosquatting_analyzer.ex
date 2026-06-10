defmodule TamanduaServer.Detection.TyposquattingAnalyzer do
  @moduledoc """
  Typosquatting Detection Analyzer.

  Detects package name typosquatting attacks using two methods:
  1. **Levenshtein distance**: Catches simple character swaps, insertions, deletions (distance <= 2)
  2. **Keyboard-adjacent substitution**: Catches visual masquerading (0->O, 1->l, 5->S, etc.)

  ## Supported Ecosystems

  - npm (Node.js)
  - pypi (Python)
  - cargo (Rust)
  - gem (Ruby)
  - go (Go modules)

  ## Examples

      # Levenshtein distance = 1
      check_typosquatting("npm", "lodas")
      # => {:typosquatting, %{similar_to: ["lodash"], detection_method: "levenshtein"}}

      # Keyboard-adjacent (0 looks like O)
      check_typosquatting("npm", "l0dash")
      # => {:typosquatting, %{similar_to: ["lodash"], detection_method: "keyboard_adjacent"}}

      # Exact match (not suspicious)
      check_typosquatting("npm", "lodash")
      # => :ok

  ## Performance

  Uses ETS tables for fast in-memory lookups with O(1) access time.
  Levenshtein comparisons limited to popular package list (typically < 1000 packages per ecosystem).
  """

  require Logger
  alias TamanduaServer.Detection.Levenshtein

  @keyboard_adjacent %{
    "l" => ["1", "I", "i"],
    "1" => ["l", "I"],
    "0" => ["O", "o"],
    "O" => ["0"],
    "o" => ["0"],
    "5" => ["S", "s"],
    "S" => ["5"],
    "s" => ["5"],
    "I" => ["l", "1"],
    "i" => ["l", "1"]
  }

  @ecosystems ["npm", "pypi", "cargo", "gem", "go"]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Initialize ETS tables and load popular packages for all ecosystems.
  Should be called on application start or in test setup.
  """
  def init do
    # Create ETS table if it doesn't exist
    unless :ets.whereis(:popular_packages) != :undefined do
      :ets.new(:popular_packages, [:set, :public, :named_table, read_concurrency: true])
    end

    # Load popular packages for each ecosystem
    for ecosystem <- @ecosystems do
      packages = load_popular_packages(ecosystem)
      :ets.insert(:popular_packages, {ecosystem, packages})
      Logger.info("[TyposquattingAnalyzer] Loaded #{MapSet.size(packages)} popular #{ecosystem} packages")
    end

    :ok
  end

  @doc """
  Check if a package name is a typosquatting attempt.

  Returns:
  - `:ok` if package is legitimate (exact match or no similar packages)
  - `{:typosquatting, info}` if package appears to be typosquatting

  The info map contains:
  - `similar_to`: List of popular packages this might be typosquatting
  - `detection_method`: "levenshtein" | "keyboard_adjacent" | "both"
  - `suspicious_package`: The package name being checked
  """
  @spec check_typosquatting(String.t(), String.t()) :: :ok | {:typosquatting, map()}
  def check_typosquatting(ecosystem, package_name) do
    # Strip namespace prefix for comparison
    base_name = strip_namespace(package_name)

    # Get popular packages for this ecosystem
    popular = get_popular_packages(ecosystem)

    # Skip if exact match in popular packages
    if MapSet.member?(popular, base_name) do
      :ok
    else
      # Check Levenshtein distance
      levenshtein_matches = find_levenshtein_matches(popular, base_name)

      # Check keyboard-adjacent
      keyboard_matches = find_keyboard_matches(popular, base_name)

      build_result(package_name, levenshtein_matches, keyboard_matches)
    end
  end

  @doc """
  Load popular packages from priv/popular_packages/{ecosystem}.txt file.
  Returns a MapSet of package names.
  """
  @spec load_popular_packages(String.t()) :: MapSet.t()
  def load_popular_packages(ecosystem) do
    path = :code.priv_dir(:tamandua_server)
           |> to_string()
           |> Path.join("popular_packages/#{ecosystem}.txt")

    case File.read(path) do
      {:ok, content} ->
        content
        |> String.split("\n", trim: true)
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))
        |> MapSet.new()

      {:error, reason} ->
        Logger.warning("[TyposquattingAnalyzer] Failed to load #{ecosystem}.txt: #{inspect(reason)}")
        MapSet.new()
    end
  end

  @doc """
  Strip namespace/scope prefix from package names.

  Examples:
  - "@babel/core" -> "core"
  - "@company/lodash" -> "lodash"
  - "lodash" -> "lodash"
  """
  @spec strip_namespace(String.t()) :: String.t()
  def strip_namespace(package_name) do
    case String.split(package_name, "/", parts: 2) do
      ["@" <> _scope, name] -> name
      [name] -> name
      _ -> package_name
    end
  end

  @doc """
  Check if two strings differ by a single keyboard-adjacent character substitution.

  Examples:
  - "l0dash" vs "lodash" -> true (0 and o are adjacent)
  - "1odash" vs "lodash" -> true (1 and l are adjacent)
  - "lodash" vs "xyz" -> false
  """
  @spec keyboard_adjacent?(String.t(), String.t()) :: boolean()
  def keyboard_adjacent?(str1, str2) do
    # Must be same length for single substitution
    if String.length(str1) == String.length(str2) do
      chars1 = String.graphemes(str1)
      chars2 = String.graphemes(str2)

      # Count differences and check if they're keyboard-adjacent
      differences = Enum.zip(chars1, chars2)
                    |> Enum.filter(fn {c1, c2} -> c1 != c2 end)

      case differences do
        # Exactly one difference
        [{c1, c2}] ->
          is_adjacent_pair?(c1, c2)

        # No differences or multiple differences
        _ ->
          false
      end
    else
      false
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp get_popular_packages(ecosystem) do
    case :ets.lookup(:popular_packages, ecosystem) do
      [{^ecosystem, packages}] -> packages
      [] -> MapSet.new()
    end
  end

  defp find_levenshtein_matches(popular, package_name) do
    popular
    |> Enum.filter(fn popular_pkg ->
      distance = Levenshtein.compare(popular_pkg, package_name)
      distance >= 1 and distance <= 2
    end)
  end

  defp find_keyboard_matches(popular, package_name) do
    popular
    |> Enum.filter(fn popular_pkg ->
      keyboard_adjacent?(package_name, popular_pkg)
    end)
  end

  defp build_result(package_name, levenshtein_matches, keyboard_matches) do
    all_matches = (levenshtein_matches ++ keyboard_matches) |> Enum.uniq()

    if Enum.empty?(all_matches) do
      :ok
    else
      detection_method = cond do
        !Enum.empty?(levenshtein_matches) && !Enum.empty?(keyboard_matches) -> "both"
        !Enum.empty?(levenshtein_matches) -> "levenshtein"
        !Enum.empty?(keyboard_matches) -> "keyboard_adjacent"
      end

      {:typosquatting, %{
        suspicious_package: package_name,
        similar_to: all_matches,
        detection_method: detection_method
      }}
    end
  end

  defp is_adjacent_pair?(c1, c2) do
    # Check if c1 -> c2 is a keyboard-adjacent substitution
    adjacent_chars = Map.get(@keyboard_adjacent, c1, [])
    adjacent_chars_reverse = Map.get(@keyboard_adjacent, c2, [])

    c2 in adjacent_chars or c1 in adjacent_chars_reverse
  end
end
