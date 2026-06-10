defmodule TamanduaServer.Detection.YaraScanner do
  @moduledoc """
  YARA rule scanner using the yara CLI tool.

  Provides file and memory scanning capabilities using YARA rules stored
  in the priv/yara_rules directory. Results are cached by file hash to
  avoid re-scanning identical files.

  ## Usage

      # Scan a file on disk
      {:ok, matches} = YaraScanner.scan_file("/path/to/suspicious.exe")

      # Scan binary data (e.g., from agent upload)
      {:ok, matches} = YaraScanner.scan_bytes(binary_data)

      # Check if YARA is available
      YaraScanner.available?()

  ## Match Format

  Each match is a map with:
  - `:rule` - The YARA rule name that matched
  - `:file` - The file path scanned
  - `:tags` - Rule tags (if any)
  - `:meta` - Rule metadata (severity, mitre_attack, etc.)
  - `:strings` - Matched string identifiers and offsets
  """

  require Logger
  alias TamanduaServer.OSCommand

  @rules_dir "priv/yara_rules"
  @cache_ttl_ms :timer.minutes(30)
  @scan_timeout_ms :timer.seconds(30)

  # ETS table for caching scan results by hash
  @cache_table :yara_scan_cache

  @doc """
  Initialize the YARA scanner cache.
  Should be called during application startup.
  """
  def init do
    if :ets.whereis(@cache_table) == :undefined do
      :ets.new(@cache_table, [:set, :public, :named_table, read_concurrency: true])
      Logger.info("YARA scanner cache initialized")
    end

    :ok
  end

  @doc """
  Check if the yara CLI tool is available on the system.
  """
  @spec available?() :: boolean()
  def available? do
    yara_executable() != nil
  end

  @doc """
  Get the yara executable path.
  """
  @spec yara_executable() :: String.t() | nil
  def yara_executable do
    case OSCommand.run("yara", ["--version"]) do
      {_, 0} -> "yara"
      _ -> nil
    end
  end

  @doc """
  Get all YARA rule files from the rules directory.
  """
  @spec get_rule_files() :: [String.t()]
  def get_rule_files do
    rules_path = get_rules_path()

    case File.ls(rules_path) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".yar"))
        |> Enum.map(&Path.join(rules_path, &1))

      {:error, reason} ->
        Logger.warning("Failed to list YARA rules directory: #{inspect(reason)}")
        []
    end
  end

  @doc """
  Compile all YARA rules into a single compiled rules file.
  This improves scan performance when scanning multiple files.

  Returns the path to the compiled rules file.
  """
  @spec compile_rules() :: {:ok, String.t()} | {:error, term()}
  def compile_rules do
    rule_files = get_rule_files()

    if Enum.empty?(rule_files) do
      {:error, :no_rules}
    else
      compiled_path = Path.join(System.tmp_dir!(), "tamandua_yara_rules.yarc")

      if yara_compiler_available?() do
        args = rule_files ++ [compiled_path]

        case OSCommand.run("yarac", args, stderr_to_stdout: true) do
          {_, 0} ->
            Logger.info("Compiled #{length(rule_files)} YARA rule files to #{compiled_path}")
            {:ok, compiled_path}

          {error, _} ->
            Logger.error("YARA rule compilation failed: #{error}")
            {:error, {:compilation_failed, error}}

          {:error, reason} ->
            {:error, reason}
        end
      else
        {:error, :yarac_not_found}
      end
    end
  end

  @doc """
  Scan a file using all available YARA rules.

  Options:
  - `:timeout` - Scan timeout in milliseconds (default: 30s)
  - `:skip_cache` - Skip cache lookup (default: false)

  Returns `{:ok, matches}` where matches is a list of match maps,
  or `{:error, reason}` if the scan failed.
  """
  @spec scan_file(String.t(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def scan_file(file_path, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @scan_timeout_ms)
    skip_cache = Keyword.get(opts, :skip_cache, false)

    cond do
      # Check if file exists
      not File.exists?(file_path) ->
        {:error, :file_not_found}

      # Try to get cached result by file hash
      not skip_cache and match?({:ok, _}, get_cached_result(file_path)) ->
        {:ok, cached} = get_cached_result(file_path)
        Logger.debug("YARA cache hit for #{file_path}")
        {:ok, cached}

      # Check if yara is available
      yara_executable() == nil ->
        {:error, :yara_not_installed}

      # No rule files
      get_rule_files() == [] ->
        {:ok, []}

      # Perform the scan
      true ->
        do_scan_file(file_path, timeout, skip_cache)
    end
  end

  defp do_scan_file(file_path, timeout, _skip_cache) do
    yara = yara_executable()
    rule_files = get_rule_files()

    # Scan with each rule file and aggregate results
    results =
      rule_files
      |> Task.async_stream(
        fn rule_file -> scan_with_rule_file(yara, rule_file, file_path, timeout) end,
        timeout: timeout + 5000,
        on_timeout: :kill_task
      )
      |> Enum.flat_map(fn
        {:ok, {:ok, matches}} ->
          matches

        {:ok, {:error, reason}} ->
          Logger.warning("YARA scan error: #{inspect(reason)}")
          []

        {:exit, :timeout} ->
          Logger.warning("YARA scan timed out for #{file_path}")
          []
      end)

    # Cache the result
    cache_result(file_path, results)

    {:ok, results}
  end

  @doc """
  Scan binary data using YARA rules.

  Writes the data to a temporary file, scans it, and removes the file.

  Options:
  - `:timeout` - Scan timeout in milliseconds (default: 30s)
  - `:hash` - Pre-computed SHA256 hash for caching (optional)
  - `:file_type` - File type hint for logging (optional)
  """
  @spec scan_bytes(binary(), keyword()) :: {:ok, [map()]} | {:error, term()}
  def scan_bytes(bytes, opts \\ []) when is_binary(bytes) do
    hash = Keyword.get(opts, :hash)

    # Check cache by hash if provided
    case hash && get_cached_result_by_hash(hash) do
      {:ok, cached} ->
        Logger.debug("YARA cache hit for hash #{hash}")
        {:ok, cached}

      _ ->
        do_scan_bytes(bytes, opts)
    end
  end

  defp do_scan_bytes(bytes, opts) do
    hash = Keyword.get(opts, :hash)
    file_type = Keyword.get(opts, :file_type, "unknown")

    # Create temp file with appropriate extension
    ext =
      case file_type do
        "pe" -> ".exe"
        "elf" -> ".elf"
        "macho" -> ".macho"
        "script" -> ".txt"
        _ -> ".bin"
      end

    temp_path =
      Path.join(
        System.tmp_dir!(),
        "yara_scan_#{:rand.uniform(1_000_000)}#{ext}"
      )

    try do
      File.write!(temp_path, bytes)

      case scan_file(temp_path, Keyword.put(opts, :skip_cache, true)) do
        {:ok, matches} ->
          # Cache by hash if provided
          if hash, do: cache_result_by_hash(hash, matches)
          {:ok, matches}

        error ->
          error
      end
    after
      File.rm(temp_path)
    end
  end

  @doc """
  Scan an event that may contain file content.

  For file_create, file_modify, and process_create events that include
  binary content or a file path, performs a YARA scan.

  Returns:
  - `{:ok, matches}` - Scan completed with matches (may be empty list)
  - `{:error, reason}` - Scan failed
  - `:skip` - Event doesn't contain scannable content
  """
  @spec scan_event(map()) :: {:ok, [map()]} | {:error, term()} | :skip
  def scan_event(event) do
    event_type = event[:event_type] || event["event_type"]
    payload = event[:payload] || event["payload"] || %{}
    content = payload[:content] || payload["content"]
    path = payload[:path] || payload["path"]
    hash = payload[:sha256] || payload["sha256"]

    cond do
      # Event has binary content to scan
      content != nil ->
        scan_bytes(content, hash: hash)

      # Event has a file path we can scan
      event_type in [:file_create, :file_modify, "file_create", "file_modify"] and path != nil ->
        # Only scan if file is local to the server (agent-side scanning is preferred)
        # This handles cases where files are uploaded for analysis
        if File.exists?(path) do
          scan_file(path)
        else
          :skip
        end

      # Process create with an executable path - check cache by hash only
      event_type in [:process_create, "process_create"] and hash != nil ->
        case get_cached_result_by_hash(hash) do
          {:ok, cached} -> {:ok, cached}
          # Don't scan remote files, rely on agent
          :miss -> :skip
        end

      true ->
        :skip
    end
  end

  @doc """
  Convert YARA matches to detection format for the engine.
  """
  @spec matches_to_detections([map()]) :: [map()]
  def matches_to_detections(matches) do
    Enum.map(matches, fn match ->
      meta = match[:meta] || %{}
      severity = meta[:severity] || "medium"
      techniques = parse_mitre_attack(meta[:mitre_attack])

      %{
        type: :yara,
        rule_name: match[:rule],
        confidence: severity_to_confidence(severity),
        description: meta[:description] || "YARA rule #{match[:rule]} matched",
        mitre_tactics: infer_tactics_from_techniques(techniques),
        mitre_techniques: techniques,
        # Extract author_pubkey for bounty payments (Solana base58 address)
        rule_author_pubkey: meta[:author_pubkey],
        meta: %{
          rule_file: match[:rule_file],
          tags: match[:tags],
          malware_family: meta[:family],
          author: meta[:author],
          author_pubkey: meta[:author_pubkey],
          matched_strings: length(match[:strings] || [])
        }
      }
    end)
  end

  defp severity_to_confidence(severity) do
    case severity do
      "critical" -> 0.95
      "high" -> 0.85
      "medium" -> 0.70
      "low" -> 0.50
      "informational" -> 0.30
      _ -> 0.60
    end
  end

  defp infer_tactics_from_techniques(techniques) do
    techniques
    |> Enum.flat_map(fn technique ->
      case TamanduaServer.Detection.Mitre.get_technique(technique) do
        nil -> []
        tech -> tech.tactics
      end
    end)
    |> Enum.uniq()
  end

  defp parse_mitre_attack(nil), do: []

  defp parse_mitre_attack(mitre_str) when is_binary(mitre_str) do
    mitre_str
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&String.starts_with?(&1, "T"))
  end

  @doc """
  Clear the scan cache.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    if :ets.whereis(@cache_table) != :undefined do
      :ets.delete_all_objects(@cache_table)
    end

    :ok
  end

  @doc """
  Get cache statistics.
  """
  @spec cache_stats() :: map()
  def cache_stats do
    if :ets.whereis(@cache_table) != :undefined do
      size = :ets.info(@cache_table, :size)
      memory = :ets.info(@cache_table, :memory) * :erlang.system_info(:wordsize)

      %{
        entries: size,
        memory_bytes: memory
      }
    else
      %{entries: 0, memory_bytes: 0}
    end
  end

  # Private functions

  defp get_rules_path do
    Application.app_dir(:tamandua_server, @rules_dir)
  rescue
    _ ->
      # Fallback for development/testing
      Path.join([File.cwd!(), "apps", "tamandua_server", @rules_dir])
  end

  defp scan_with_rule_file(yara, rule_file, file_path, timeout) do
    # YARA flags:
    # -s: print matched strings
    # -m: print metadata
    # -w: disable warnings
    args = ["-s", "-m", "-w", rule_file, file_path]

    try do
      case OSCommand.run(yara, args, stderr_to_stdout: true, timeout: timeout) do
        {output, 0} ->
          matches = parse_yara_output(output, rule_file)
          {:ok, matches}

        {output, 1} when output == "" ->
          # Exit code 1 with no output means no matches
          {:ok, []}

        {error, code} ->
          Logger.warning("YARA scan failed (code #{code}): #{String.slice(error, 0, 200)}")
          {:error, {:scan_failed, code, error}}

        {:error, reason} ->
          {:error, reason}
      end
    catch
      :exit, {:timeout, _} ->
        {:error, :timeout}
    end
  end

  defp yara_compiler_available? do
    case OSCommand.run("yarac", ["--version"]) do
      {_, 0} -> true
      _ -> false
    end
  end

  defp parse_yara_output(output, rule_file) do
    output
    |> String.split("\n", trim: true)
    |> parse_yara_lines(rule_file, [], nil)
  end

  # Parse YARA output lines into structured matches
  # Format: rule_name [tags] file_path
  # Followed by: meta: key=value lines
  # Followed by: 0xoffset:$string_id: matched_data lines
  defp parse_yara_lines([], _rule_file, matches, current_match) do
    if current_match do
      Enum.reverse([current_match | matches])
    else
      Enum.reverse(matches)
    end
  end

  defp parse_yara_lines([line | rest], rule_file, matches, current_match) do
    cond do
      # New rule match line (starts with word, not hex offset or whitespace)
      String.contains?(line, " ") and not String.starts_with?(line, "0x") and
        not String.starts_with?(line, " ") and not String.starts_with?(line, "\t") ->
        # Save previous match if exists
        matches = if current_match, do: [current_match | matches], else: matches

        # Parse the rule match line
        {rule_name, tags, file_path} = parse_rule_line(line)

        new_match = %{
          rule: rule_name,
          file: file_path,
          rule_file: Path.basename(rule_file),
          tags: tags,
          meta: %{},
          strings: []
        }

        parse_yara_lines(rest, rule_file, matches, new_match)

      # Metadata line (indented key=value)
      current_match != nil and String.match?(line, ~r/^\s+\w+\s*=/) ->
        meta = parse_meta_line(line)
        updated_match = %{current_match | meta: Map.merge(current_match.meta, meta)}
        parse_yara_lines(rest, rule_file, matches, updated_match)

      # String match line (0xOFFSET:$identifier: data)
      current_match != nil and String.starts_with?(line, "0x") ->
        string_match = parse_string_line(line)
        updated_strings = current_match.strings ++ [string_match]
        updated_match = %{current_match | strings: updated_strings}
        parse_yara_lines(rest, rule_file, matches, updated_match)

      # Unknown line, skip
      true ->
        parse_yara_lines(rest, rule_file, matches, current_match)
    end
  end

  defp parse_rule_line(line) do
    # Format: "RuleName [tag1,tag2] /path/to/file"
    # or: "RuleName /path/to/file"
    case Regex.run(~r/^(\w+)\s*(?:\[([^\]]*)\])?\s+(.+)$/, line) do
      [_, rule_name, tags_str, file_path] ->
        tags =
          if tags_str && tags_str != "" do
            String.split(tags_str, ",", trim: true) |> Enum.map(&String.trim/1)
          else
            []
          end

        {rule_name, tags, String.trim(file_path)}

      _ ->
        # Fallback: split on whitespace
        parts = String.split(line, ~r/\s+/, parts: 2)
        {List.first(parts, "unknown"), [], List.last(parts, "")}
    end
  end

  defp parse_meta_line(line) do
    # Format: "  key = value" or "  key = \"quoted value\""
    case Regex.run(~r/^\s+(\w+)\s*=\s*(.+)$/, line) do
      [_, key, value] ->
        # Remove quotes if present
        value =
          value
          |> String.trim()
          |> String.trim("\"")

        %{String.to_atom(key) => value}

      _ ->
        %{}
    end
  end

  defp parse_string_line(line) do
    # Format: "0x1234:$string_id: matched data"
    case Regex.run(~r/^(0x[0-9a-fA-F]+):(\$\w+):\s*(.*)$/, line) do
      [_, offset, identifier, data] ->
        %{
          offset: offset,
          identifier: identifier,
          # Truncate long matches
          data: String.slice(data, 0, 100)
        }

      _ ->
        %{offset: "0x0", identifier: "$unknown", data: line}
    end
  end

  # Cache functions

  defp get_cached_result(file_path) do
    case File.stat(file_path) do
      {:ok, %{mtime: mtime, size: size}} ->
        cache_key = {:file, file_path, mtime, size}
        lookup_cache(cache_key)

      {:error, _} ->
        :miss
    end
  end

  defp get_cached_result_by_hash(hash) when is_binary(hash) do
    lookup_cache({:hash, hash})
  end

  defp get_cached_result_by_hash(_), do: :miss

  defp lookup_cache(key) do
    if :ets.whereis(@cache_table) != :undefined do
      case :ets.lookup(@cache_table, key) do
        [{^key, result, timestamp}] ->
          if System.system_time(:millisecond) - timestamp < @cache_ttl_ms do
            {:ok, result}
          else
            :ets.delete(@cache_table, key)
            :miss
          end

        [] ->
          :miss
      end
    else
      :miss
    end
  end

  defp cache_result(file_path, results) do
    case File.stat(file_path) do
      {:ok, %{mtime: mtime, size: size}} ->
        cache_key = {:file, file_path, mtime, size}
        insert_cache(cache_key, results)

      {:error, _} ->
        :ok
    end
  end

  defp cache_result_by_hash(hash, results) when is_binary(hash) do
    insert_cache({:hash, hash}, results)
  end

  defp cache_result_by_hash(_, _), do: :ok

  defp insert_cache(key, results) do
    if :ets.whereis(@cache_table) != :undefined do
      timestamp = System.system_time(:millisecond)
      :ets.insert(@cache_table, {key, results, timestamp})
    end

    :ok
  end
end
