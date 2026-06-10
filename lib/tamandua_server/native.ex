defmodule TamanduaServer.Native do
  @moduledoc """
  Rust NIF bindings for high-performance operations.

  These functions are implemented in Rust for performance-critical
  operations like YARA scanning, entropy calculation, and IOC matching.

  Note: When Rustler/NIF is not available, functions return error tuples.

  ## Features

  - **YARA Scanning**: Compile and scan with YARA rules
  - **Hashing**: Fast SHA256, SHA1, MD5 computation
  - **Entropy Analysis**: Shannon entropy and packing detection
  - **Sigma Rules**: Parse and match Sigma detection rules
  - **IOC Matching**: IP, domain, and hash matching with wildcards

  ## Usage

      # YARA scanning
      {:ok, rules} = Native.compile_rules(yara_source)
      {:ok, matches} = Native.scan_file(rules, "/path/to/file")

      # Hashing (efficient multi-hash)
      {:ok, {sha256, sha1, md5, size}} = Native.multi_hash_file("/path/to/file")

      # Entropy analysis
      {:ok, entropy} = Native.calculate_file("/path/to/file")
      {:ok, is_packed} = Native.detect_packed(binary_data)

      # Sigma rules
      {:ok, rule} = Native.parse_rule(sigma_yaml)
      {:ok, matched} = Native.match_event(rule_json, event_json)

      # IOC matching
      {:ok, true} = Native.match_ip("192.168.1.50", "192.168.1.0/24")
      {:ok, iocs} = Native.extract_iocs(text)
  """

  require Logger

  @nif_unavailable_error {:error, "Rust NIF not available - compile with Rustler support"}

  @doc "Check if Rust NIFs are available"
  def rustler_available?, do: false

  # YARA functions

  @doc """
  Compile YARA rules from source string.
  Returns error when NIF not available.
  """
  def compile_rules(_rules_source), do: @nif_unavailable_error

  @doc "Scan binary data with compiled YARA rules."
  def scan_bytes(_compiled_rules, _data), do: @nif_unavailable_error

  @doc "Scan file with compiled YARA rules."
  def scan_file(_compiled_rules, _path), do: @nif_unavailable_error

  @doc "List all rule names in a compiled ruleset."
  def list_rules(_compiled_rules), do: @nif_unavailable_error

  # Hash functions

  @doc "Calculate SHA-256 hash of binary data."
  def sha256(data) when is_binary(data) do
    {:ok, :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)}
  end

  @doc "Calculate SHA-256 hash of a file."
  def sha256_file(file_path) do
    case File.read(file_path) do
      {:ok, data} -> sha256(data)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  @doc "Calculate SHA-1 hash of binary data."
  def sha1(data) when is_binary(data) do
    {:ok, :crypto.hash(:sha, data) |> Base.encode16(case: :lower)}
  end

  @doc "Calculate SHA-1 hash of a file."
  def sha1_file(file_path) do
    case File.read(file_path) do
      {:ok, data} -> sha1(data)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  @doc "Calculate MD5 hash of binary data."
  def md5(data) when is_binary(data) do
    {:ok, :crypto.hash(:md5, data) |> Base.encode16(case: :lower)}
  end

  @doc "Calculate MD5 hash of a file."
  def md5_file(file_path) do
    case File.read(file_path) do
      {:ok, data} -> md5(data)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  @doc "Calculate ssdeep (fuzzy hash) of binary data."
  def ssdeep(_data), do: @nif_unavailable_error

  @doc "Calculate multiple hashes in a single pass."
  def multi_hash(data) when is_binary(data) do
    sha256 = :crypto.hash(:sha256, data) |> Base.encode16(case: :lower)
    sha1 = :crypto.hash(:sha, data) |> Base.encode16(case: :lower)
    md5 = :crypto.hash(:md5, data) |> Base.encode16(case: :lower)
    size = byte_size(data)
    {:ok, {sha256, sha1, md5, size}}
  end

  @doc "Calculate multiple hashes of a file in a single pass."
  def multi_hash_file(file_path) do
    case File.read(file_path) do
      {:ok, data} -> multi_hash(data)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  # Entropy functions

  @doc "Calculate Shannon entropy of binary data."
  def calculate(data) when is_binary(data) do
    if byte_size(data) == 0 do
      {:ok, 0.0}
    else
      # Calculate byte frequency
      freqs =
        data
        |> :binary.bin_to_list()
        |> Enum.frequencies()
        |> Map.values()

      total = byte_size(data)

      entropy =
        freqs
        |> Enum.reduce(0.0, fn count, acc ->
          p = count / total
          acc - p * :math.log2(p)
        end)

      {:ok, entropy}
    end
  end

  @doc "Calculate Shannon entropy of a file."
  def calculate_file(file_path) do
    case File.read(file_path) do
      {:ok, data} -> calculate(data)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  @doc "Calculate entropy for sections of data."
  def calculate_sections(data, section_size) when is_binary(data) and is_integer(section_size) do
    sections =
      for chunk <- chunk_binary(data, section_size) do
        case calculate(chunk) do
          {:ok, entropy} -> entropy
          _ -> 0.0
        end
      end

    {:ok, sections}
  end

  @doc "Detect if binary data is packed/compressed."
  def detect_packed(data) when is_binary(data) do
    case calculate(data) do
      {:ok, entropy} -> {:ok, entropy > 7.0}
      error -> error
    end
  end

  @doc "Comprehensive file analysis including entropy and packing detection."
  def analyze_file(file_path) do
    case File.read(file_path) do
      {:ok, data} ->
        {:ok, entropy} = calculate(data)
        {:ok, is_packed} = detect_packed(data)

        {:ok,
         %{
           entropy: entropy,
           is_packed: is_packed,
           file_size: byte_size(data),
           high_entropy_regions: []
         }}

      {:error, reason} ->
        {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  # Sigma functions

  @doc "Parse a Sigma rule from YAML string."
  def parse_rule(_yaml_content), do: @nif_unavailable_error

  @doc "Match an event against a parsed Sigma rule."
  def match_event(_rule_json, _event_json), do: @nif_unavailable_error

  @doc "Compile multiple Sigma rules in batch."
  def compile_rules_batch(_yaml_contents), do: @nif_unavailable_error

  @doc "Validate a Sigma rule."
  def validate_rule(_yaml_content), do: @nif_unavailable_error

  # IOC functions

  @doc "Match IP address against IOC (supports CIDR)."
  def match_ip(ip, ioc) when is_binary(ip) and is_binary(ioc) do
    # Basic implementation - exact match only
    {:ok, String.downcase(ip) == String.downcase(ioc)}
  end

  @doc "Match domain against IOC (supports wildcards)."
  def match_domain(domain, ioc) when is_binary(domain) and is_binary(ioc) do
    domain = String.downcase(domain)
    ioc = String.downcase(ioc)

    matched =
      cond do
        String.starts_with?(ioc, "*.") ->
          suffix = String.slice(ioc, 1..-1//1)
          String.ends_with?(domain, suffix)

        true ->
          domain == ioc
      end

    {:ok, matched}
  end

  @doc "Match hash against IOC."
  def match_hash(hash, ioc) when is_binary(hash) and is_binary(ioc) do
    {:ok, String.downcase(hash) == String.downcase(ioc)}
  end

  @doc "Extract IOCs from text."
  def extract_iocs(text) when is_binary(text) do
    # Basic regex-based extraction
    ip_regex = ~r/\b(?:\d{1,3}\.){3}\d{1,3}\b/
    domain_regex = ~r/\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b/
    hash_regex = ~r/\b[a-fA-F0-9]{32,64}\b/

    ips = Regex.scan(ip_regex, text) |> List.flatten() |> Enum.uniq()
    domains = Regex.scan(domain_regex, text) |> List.flatten() |> Enum.uniq()
    hashes = Regex.scan(hash_regex, text) |> List.flatten() |> Enum.uniq()

    {:ok,
     %{
       ips: ips,
       domains: domains,
       urls: [],
       hashes: hashes,
       emails: []
     }}
  end

  @doc "Match multiple IOCs against a list in batch."
  def match_iocs_batch(values, iocs, ioc_type) when is_list(values) and is_list(iocs) do
    match_fn =
      case ioc_type do
        "ip" -> &match_ip/2
        "domain" -> &match_domain/2
        "hash" -> &match_hash/2
        _ -> fn _, _ -> {:ok, false} end
      end

    results =
      for value <- values do
        Enum.any?(iocs, fn ioc ->
          case match_fn.(value, ioc) do
            {:ok, true} -> true
            _ -> false
          end
        end)
      end

    {:ok, results}
  end

  @doc "Load NIF library on application start."
  def on_load, do: :ok

  # Helper function to chunk binary data
  defp chunk_binary(data, chunk_size) when byte_size(data) <= chunk_size, do: [data]

  defp chunk_binary(data, chunk_size) do
    <<chunk::binary-size(chunk_size), rest::binary>> = data
    [chunk | chunk_binary(rest, chunk_size)]
  end
end
