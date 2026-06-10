defmodule TamanduaServer.ContainerSecurity.Trivy do
  @moduledoc """
  Trivy vulnerability scanner integration.

  Supports two modes of operation:
  - CLI mode: Calls the `trivy` binary directly
  - Server mode: Sends requests to a Trivy server instance

  ## Configuration

      config :tamandua_server, :trivy,
        enabled: true,
        mode: :cli,  # or :server
        server_url: "http://localhost:4954",
        timeout: 120_000,
        cache_backend: "fs",  # Trivy cache backend
        severity: "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

  ## Usage

      # Scan a container image
      Trivy.scan_image("nginx", "latest")

      # Scan with options
      Trivy.scan_image("myapp", "v1.0.0", mode: :server, timeout: 60_000)

      # Scan filesystem (for local analysis)
      Trivy.scan_filesystem("/path/to/app")
  """

  require Logger
  alias TamanduaServer.OSCommand

  @type scan_result :: {:ok, vulnerability_report()} | {:error, term()}
  @type vulnerability_report :: %{
          image: String.t(),
          tag: String.t(),
          digest: String.t() | nil,
          vulnerabilities: [vulnerability()],
          critical_count: non_neg_integer(),
          high_count: non_neg_integer(),
          medium_count: non_neg_integer(),
          low_count: non_neg_integer(),
          unknown_count: non_neg_integer(),
          scan_time: DateTime.t(),
          scanner: String.t(),
          scanner_version: String.t() | nil,
          metadata: map()
        }
  @type vulnerability :: %{
          cve: String.t(),
          severity: String.t(),
          package: String.t(),
          installed_version: String.t(),
          fixed_version: String.t() | nil,
          title: String.t() | nil,
          description: String.t() | nil,
          references: [String.t()],
          cvss_score: float() | nil,
          cvss_vector: String.t() | nil
        }

  @default_timeout 120_000
  @default_severity "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"

  @doc """
  Scan a container image for vulnerabilities.

  ## Options

  - `:mode` - `:cli` or `:server` (default from config or `:cli`)
  - `:timeout` - Timeout in milliseconds (default 120_000)
  - `:severity` - Comma-separated severity levels to include
  - `:ignore_unfixed` - If true, only show vulnerabilities with fixes available

  ## Examples

      iex> Trivy.scan_image("alpine", "3.18")
      {:ok, %{vulnerabilities: [...], critical_count: 0, ...}}

      iex> Trivy.scan_image("nginx", "latest", mode: :server)
      {:ok, %{vulnerabilities: [...], ...}}
  """
  @spec scan_image(String.t(), String.t(), keyword()) :: scan_result()
  def scan_image(image, tag, opts \\ []) do
    config = get_config()

    if not config[:enabled] do
      {:error, :trivy_disabled}
    else
      mode = Keyword.get(opts, :mode, config[:mode] || :cli)
      timeout = Keyword.get(opts, :timeout, config[:timeout] || @default_timeout)

      merged_opts =
        opts
        |> Keyword.put(:timeout, timeout)
        |> Keyword.put_new(:severity, config[:severity] || @default_severity)
        |> Keyword.put_new(:ignore_unfixed, config[:ignore_unfixed] || false)

      case mode do
        :cli -> scan_via_cli(image, tag, merged_opts)
        :server -> scan_via_server(image, tag, merged_opts, config)
        _ -> {:error, {:invalid_mode, mode}}
      end
    end
  end

  @doc """
  Scan a filesystem path for vulnerabilities.

  Useful for scanning application dependencies in a directory.

  ## Options

  Same as `scan_image/3`, plus:
  - `:scanners` - List of scanners to use (default: ["vuln", "secret"])
  """
  @spec scan_filesystem(String.t(), keyword()) :: scan_result()
  def scan_filesystem(path, opts \\ []) do
    config = get_config()

    if not config[:enabled] do
      {:error, :trivy_disabled}
    else
      mode = Keyword.get(opts, :mode, config[:mode] || :cli)
      timeout = Keyword.get(opts, :timeout, config[:timeout] || @default_timeout)

      merged_opts =
        opts
        |> Keyword.put(:timeout, timeout)
        |> Keyword.put_new(:severity, config[:severity] || @default_severity)
        |> Keyword.put_new(:scanners, ["vuln", "secret"])

      case mode do
        :cli -> scan_fs_via_cli(path, merged_opts)
        :server -> {:error, :filesystem_scan_not_supported_in_server_mode}
        _ -> {:error, {:invalid_mode, mode}}
      end
    end
  end

  @doc """
  Check if Trivy is available and configured properly.
  """
  @spec available?() :: boolean()
  def available? do
    config = get_config()

    if not config[:enabled] do
      false
    else
      case config[:mode] || :cli do
        :cli -> check_cli_available()
        :server -> check_server_available(config)
        _ -> false
      end
    end
  end

  @doc """
  Get the Trivy version.
  """
  @spec version() :: {:ok, String.t()} | {:error, term()}
  def version do
    case OSCommand.run("trivy", ["--version"], stderr_to_stdout: true) do
      {output, 0} ->
        # Parse version from output like "Version: 0.48.0"
        case Regex.run(~r/Version:\s*(\S+)/, output) do
          [_, version] -> {:ok, version}
          _ -> {:ok, String.trim(output)}
        end

      {error, _} ->
        {:error, error}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  # Private Functions - CLI Mode

  defp scan_via_cli(image, tag, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    severity = Keyword.get(opts, :severity, @default_severity)
    ignore_unfixed = Keyword.get(opts, :ignore_unfixed, false)

    image_ref = "#{image}:#{tag}"

    args =
      ["image", "--format", "json", "--quiet", "--severity", severity] ++
        if(ignore_unfixed, do: ["--ignore-unfixed"], else: []) ++
        [image_ref]

    Logger.info("Running Trivy scan: trivy #{Enum.join(args, " ")}")

    case OSCommand.run("trivy", args, stderr_to_stdout: true, timeout: timeout) do
      {output, 0} ->
        parse_trivy_output(output, image, tag)

      {output, exit_code} ->
        Logger.error("Trivy scan failed (exit #{exit_code}): #{String.slice(output, 0, 500)}")
        {:error, {:trivy_failed, exit_code, output}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e in ErlangError ->
      case e do
        %ErlangError{original: :enoent} ->
          Logger.error("Trivy binary not found in PATH")
          {:error, :trivy_not_found}

        %ErlangError{original: :timeout} ->
          Logger.error("Trivy scan timed out")
          {:error, :timeout}

        _ ->
          Logger.error("Trivy scan error: #{inspect(e)}")
          {:error, {:scan_error, Exception.message(e)}}
      end

    e ->
      Logger.error("Trivy scan error: #{inspect(e)}")
      {:error, {:scan_error, Exception.message(e)}}
  end

  defp scan_fs_via_cli(path, opts) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    severity = Keyword.get(opts, :severity, @default_severity)
    scanners = Keyword.get(opts, :scanners, ["vuln", "secret"])

    args =
      [
        "fs",
        "--format",
        "json",
        "--quiet",
        "--severity",
        severity,
        "--scanners",
        Enum.join(scanners, ",")
      ] ++
        [path]

    Logger.info("Running Trivy filesystem scan: trivy #{Enum.join(args, " ")}")

    case OSCommand.run("trivy", args, stderr_to_stdout: true, timeout: timeout) do
      {output, 0} ->
        parse_trivy_fs_output(output, path)

      {output, exit_code} ->
        Logger.error("Trivy fs scan failed (exit #{exit_code}): #{String.slice(output, 0, 500)}")
        {:error, {:trivy_failed, exit_code, output}}

      {:error, reason} ->
        {:error, reason}
    end
  rescue
    e in ErlangError ->
      case e do
        %ErlangError{original: :enoent} ->
          {:error, :trivy_not_found}

        %ErlangError{original: :timeout} ->
          {:error, :timeout}

        _ ->
          {:error, {:scan_error, Exception.message(e)}}
      end

    e ->
      {:error, {:scan_error, Exception.message(e)}}
  end

  # Private Functions - Server Mode

  defp scan_via_server(image, tag, opts, config) do
    server_url = config[:server_url] || "http://localhost:4954"
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    severity = Keyword.get(opts, :severity, @default_severity)

    image_ref = "#{image}:#{tag}"

    # Trivy server expects a PUT request to /image endpoint
    url = "#{server_url}/image"

    headers = [
      {"Content-Type", "application/json"},
      {"Accept", "application/json"}
    ]

    body =
      Jason.encode!(%{
        "image" => image_ref,
        "severity" => severity
      })

    Logger.info("Sending scan request to Trivy server: #{url}")

    case http_request(:put, url, headers, body, timeout) do
      {:ok, %{status: status, body: response_body}} when status in 200..299 ->
        parse_trivy_output(response_body, image, tag)

      {:ok, %{status: status, body: response_body}} ->
        Logger.error(
          "Trivy server returned status #{status}: #{String.slice(response_body, 0, 500)}"
        )

        {:error, {:server_error, status, response_body}}

      {:error, reason} ->
        Logger.error("Failed to connect to Trivy server: #{inspect(reason)}")
        {:error, {:connection_failed, reason}}
    end
  end

  # HTTP client abstraction (uses :httpc from stdlib)
  defp http_request(method, url, headers, body, timeout) do
    # Ensure :inets is started
    :inets.start()
    :ssl.start()

    http_headers =
      Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    request =
      case method do
        :put -> {String.to_charlist(url), http_headers, ~c"application/json", body}
        :get -> {String.to_charlist(url), http_headers}
        :post -> {String.to_charlist(url), http_headers, ~c"application/json", body}
      end

    http_opts = [
      timeout: timeout,
      connect_timeout: 10_000,
      ssl: [verify: :verify_none]
    ]

    case :httpc.request(method, request, http_opts, body_format: :binary) do
      {:ok, {{_http_version, status_code, _reason_phrase}, _resp_headers, resp_body}} ->
        {:ok, %{status: status_code, body: to_string(resp_body)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private Functions - Output Parsing

  defp parse_trivy_output(json_output, image, tag) do
    case Jason.decode(json_output) do
      {:ok, data} ->
        vulnerabilities = extract_vulnerabilities(data)
        counts = count_by_severity(vulnerabilities)

        report = %{
          image: image,
          tag: tag,
          digest: extract_digest(data),
          vulnerabilities: vulnerabilities,
          critical_count: counts["CRITICAL"] || 0,
          high_count: counts["HIGH"] || 0,
          medium_count: counts["MEDIUM"] || 0,
          low_count: counts["LOW"] || 0,
          unknown_count: counts["UNKNOWN"] || 0,
          scan_time: DateTime.utc_now(),
          scanner: "trivy",
          scanner_version: extract_scanner_version(data),
          metadata: extract_metadata(data)
        }

        {:ok, report}

      {:error, decode_error} ->
        Logger.error("Failed to parse Trivy JSON output: #{inspect(decode_error)}")
        Logger.debug("Raw output: #{String.slice(json_output, 0, 1000)}")
        {:error, {:json_parse_error, decode_error}}
    end
  end

  defp parse_trivy_fs_output(json_output, path) do
    case Jason.decode(json_output) do
      {:ok, data} ->
        vulnerabilities = extract_vulnerabilities(data)
        counts = count_by_severity(vulnerabilities)

        report = %{
          image: path,
          tag: "filesystem",
          digest: nil,
          vulnerabilities: vulnerabilities,
          critical_count: counts["CRITICAL"] || 0,
          high_count: counts["HIGH"] || 0,
          medium_count: counts["MEDIUM"] || 0,
          low_count: counts["LOW"] || 0,
          unknown_count: counts["UNKNOWN"] || 0,
          scan_time: DateTime.utc_now(),
          scanner: "trivy",
          scanner_version: extract_scanner_version(data),
          metadata: extract_metadata(data)
        }

        {:ok, report}

      {:error, decode_error} ->
        {:error, {:json_parse_error, decode_error}}
    end
  end

  defp extract_vulnerabilities(data) do
    # Trivy JSON format has Results[] array, each with Vulnerabilities[]
    results = data["Results"] || []

    Enum.flat_map(results, fn result ->
      target = result["Target"] || "unknown"
      result_type = result["Type"] || "unknown"
      vulns = result["Vulnerabilities"] || []

      Enum.map(vulns, fn vuln ->
        %{
          cve: vuln["VulnerabilityID"] || "UNKNOWN",
          severity: String.upcase(vuln["Severity"] || "UNKNOWN"),
          package: vuln["PkgName"] || "unknown",
          installed_version: vuln["InstalledVersion"] || "unknown",
          fixed_version: vuln["FixedVersion"],
          title: vuln["Title"],
          description: vuln["Description"],
          references: vuln["References"] || [],
          cvss_score: extract_cvss_score(vuln),
          cvss_vector: extract_cvss_vector(vuln),
          target: target,
          target_type: result_type,
          published_date: vuln["PublishedDate"],
          last_modified_date: vuln["LastModifiedDate"],
          data_source: vuln["DataSource"]
        }
      end)
    end)
  end

  defp extract_cvss_score(vuln) do
    # Try CVSS v3 first, then v2
    cond do
      cvss3 = get_in(vuln, ["CVSS", "nvd", "V3Score"]) -> cvss3
      cvss3 = get_in(vuln, ["CVSS", "redhat", "V3Score"]) -> cvss3
      cvss2 = get_in(vuln, ["CVSS", "nvd", "V2Score"]) -> cvss2
      true -> nil
    end
  end

  defp extract_cvss_vector(vuln) do
    cond do
      v3 = get_in(vuln, ["CVSS", "nvd", "V3Vector"]) -> v3
      v3 = get_in(vuln, ["CVSS", "redhat", "V3Vector"]) -> v3
      v2 = get_in(vuln, ["CVSS", "nvd", "V2Vector"]) -> v2
      true -> nil
    end
  end

  defp extract_digest(data) do
    # Try to get image digest from metadata
    get_in(data, ["Metadata", "RepoDigests"]) |> List.first()
  rescue
    _ -> nil
  end

  defp extract_scanner_version(data) do
    data["SchemaVersion"] |> to_string()
  rescue
    _ -> nil
  end

  defp extract_metadata(data) do
    metadata = data["Metadata"] || %{}

    %{
      os_family: metadata["OS"] && metadata["OS"]["Family"],
      os_name: metadata["OS"] && metadata["OS"]["Name"],
      image_id: metadata["ImageID"],
      repo_tags: metadata["RepoTags"] || [],
      repo_digests: metadata["RepoDigests"] || [],
      created: metadata["Created"]
    }
  end

  defp count_by_severity(vulnerabilities) do
    Enum.reduce(vulnerabilities, %{}, fn vuln, acc ->
      severity = vuln[:severity] || "UNKNOWN"
      Map.update(acc, severity, 1, &(&1 + 1))
    end)
  end

  # Private Functions - Availability Checks

  defp check_cli_available do
    case OSCommand.run("trivy", ["--version"], stderr_to_stdout: true) do
      {_output, 0} -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  defp check_server_available(config) do
    server_url = config[:server_url] || "http://localhost:4954"
    health_url = "#{server_url}/healthz"

    case http_request(:get, health_url, [], "", 5_000) do
      {:ok, %{status: status}} when status in 200..299 -> true
      _ -> false
    end
  rescue
    _ -> false
  end

  # Configuration

  defp get_config do
    Application.get_env(:tamandua_server, :trivy, [])
    |> Keyword.put_new(:enabled, true)
    |> Keyword.put_new(:mode, :cli)
    |> Keyword.put_new(:timeout, @default_timeout)
    |> Keyword.put_new(:severity, @default_severity)
  end
end
