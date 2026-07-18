defmodule TamanduaServer.Detection.ThreatIntel.AbuseCh do
  @moduledoc """
  Client for Abuse.ch services: MalwareBazaar, URLhaus, ThreatFox.

  These are free-to-use threat intelligence feeds that do not require API keys.
  They provide high-quality IOCs for malware, malicious URLs, and various threat indicators.

  ## Services

  - **MalwareBazaar**: Database of malware samples with file hashes, signatures, and metadata
  - **URLhaus**: Database of malicious URLs used for malware distribution
  - **ThreatFox**: IOC sharing platform with various indicator types

  ## Usage

      # Query a specific hash
      AbuseCh.query_hash("abc123...")

      # Get recent malware samples
      AbuseCh.get_recent_samples(100)

      # Check if a URL is malicious
      AbuseCh.query_url("http://malicious.com/payload.exe")
  """

  require Logger

  @malwarebazaar_api "https://mb-api.abuse.ch/api/v1/"
  @urlhaus_api "https://urlhaus-api.abuse.ch/v1/"
  @threatfox_api "https://threatfox-api.abuse.ch/api/v1/"

  @recv_timeout 30_000

  # ============================================================================
  # MalwareBazaar API
  # ============================================================================

  @doc """
  Query MalwareBazaar for a specific SHA256 hash.

  Returns malware sample information if found.

  ## Examples

      iex> query_hash("a1b2c3...")
      {:ok, %{
        sha256: "a1b2c3...",
        sha1: "...",
        md5: "...",
        file_type: "exe",
        file_size: 123456,
        signature: "Emotet",
        first_seen: "2024-01-15",
        tags: ["trojan", "banking"],
        delivery_method: "email"
      }}

      iex> query_hash("notfound")
      {:ok, :not_found}
  """
  @spec query_hash(String.t()) :: {:ok, map() | :not_found} | {:error, term()}
  def query_hash(sha256) when is_binary(sha256) do
    body = URI.encode_query(%{query: "get_info", hash: sha256})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@malwarebazaar_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_malwarebazaar_hash_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        Logger.warning("[AbuseCh.MalwareBazaar] HTTP #{status} for hash query")
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        Logger.error("[AbuseCh.MalwareBazaar] Error: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Get recent malware samples from MalwareBazaar.

  ## Options
    - `limit` - Maximum number of samples to return (default: 100, max: 1000)

  ## Examples

      iex> get_recent_samples(50)
      {:ok, [%{sha256: "...", signature: "Emotet", ...}, ...]}
  """
  @spec get_recent_samples(pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def get_recent_samples(limit \\ 100) when is_integer(limit) and limit > 0 do
    body = URI.encode_query(%{query: "get_recent", selector: min(limit, 1000)})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@malwarebazaar_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_malwarebazaar_list_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Get detailed information about a malware sample by SHA256.

  Returns extended information including YARA rules, vendor detections, and sandbox results.
  """
  @spec get_sample_info(String.t()) :: {:ok, map() | :not_found} | {:error, term()}
  def get_sample_info(sha256) when is_binary(sha256) do
    body = URI.encode_query(%{query: "get_info", hash: sha256})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@malwarebazaar_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_malwarebazaar_info_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Query MalwareBazaar by malware signature/family name.

  ## Examples

      iex> query_signature("Emotet")
      {:ok, [%{sha256: "...", first_seen: "...", ...}, ...]}
  """
  @spec query_signature(String.t(), pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def query_signature(signature, limit \\ 100) when is_binary(signature) do
    body = URI.encode_query(%{query: "get_siginfo", signature: signature, limit: min(limit, 1000)})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(@malwarebazaar_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_malwarebazaar_list_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # URLhaus API
  # ============================================================================

  @doc """
  Query URLhaus for a specific URL.

  Returns information about the URL if it's in the database.

  ## Examples

      iex> query_url("http://evil.com/malware.exe")
      {:ok, %{
        url: "http://evil.com/malware.exe",
        url_status: "online",
        threat: "malware_download",
        host: "evil.com",
        date_added: "2024-01-15",
        payloads: [...]
      }}
  """
  @spec query_url(String.t()) :: {:ok, map() | :not_found} | {:error, term()}
  def query_url(url) when is_binary(url) do
    api_url = "#{@urlhaus_api}url/"
    body = URI.encode_query(%{url: url})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(api_url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_urlhaus_url_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Query URLhaus for all malicious URLs associated with a host.

  ## Examples

      iex> query_host("evil.com")
      {:ok, [%{url: "http://evil.com/malware.exe", ...}, ...]}
  """
  @spec query_host(String.t()) :: {:ok, [map()] | :not_found} | {:error, term()}
  def query_host(host) when is_binary(host) do
    api_url = "#{@urlhaus_api}host/"
    body = URI.encode_query(%{host: host})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(api_url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_urlhaus_host_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Get recent malicious URLs from URLhaus.

  ## Examples

      iex> get_recent_urls(100)
      {:ok, [%{url: "...", threat: "malware_download", ...}, ...]}
  """
  @spec get_recent_urls(pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def get_recent_urls(limit \\ 100) when is_integer(limit) and limit > 0 do
    api_url = "#{@urlhaus_api}urls/recent/limit/#{min(limit, 1000)}/"
    headers = [{"Accept", "application/json"}]

    case http_get(api_url, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_urlhaus_recent_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Query URLhaus for a payload hash.

  Returns information about malware payloads distributed via the URL.
  """
  @spec query_payload(String.t()) :: {:ok, map() | :not_found} | {:error, term()}
  def query_payload(hash) when is_binary(hash) do
    hash_type = case String.length(hash) do
      32 -> "md5_hash"
      64 -> "sha256_hash"
      _ -> "sha256_hash"
    end

    api_url = "#{@urlhaus_api}payload/"
    body = URI.encode_query(%{hash_type => hash})
    headers = [{"Content-Type", "application/x-www-form-urlencoded"}]

    case http_post(api_url, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_urlhaus_payload_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # ThreatFox API
  # ============================================================================

  @doc """
  Query ThreatFox for a specific IOC.

  ## Parameters
    - `ioc_type` - Type of IOC: "ip:port", "domain", "url", "md5_hash", "sha256_hash"
    - `ioc_value` - The IOC value to query

  ## Examples

      iex> query_ioc("ip:port", "192.168.1.1:443")
      {:ok, %{
        ioc: "192.168.1.1:443",
        ioc_type: "ip:port",
        threat_type: "botnet_cc",
        malware: "Emotet",
        confidence_level: 75,
        first_seen: "2024-01-15",
        tags: ["banking", "trojan"]
      }}
  """
  @spec query_ioc(String.t(), String.t()) :: {:ok, map() | :not_found} | {:error, term()}
  def query_ioc(ioc_type, ioc_value) when is_binary(ioc_type) and is_binary(ioc_value) do
    body = Jason.encode!(%{query: "search_ioc", search_term: ioc_value})
    headers = [{"Content-Type", "application/json"}]

    case http_post(@threatfox_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_threatfox_ioc_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Get recent IOCs from ThreatFox.

  ## Parameters
    - `days` - Number of days to look back (default: 7, max: 30)

  ## Examples

      iex> get_recent_iocs(7)
      {:ok, [%{ioc: "...", threat_type: "botnet_cc", ...}, ...]}
  """
  @spec get_recent_iocs(pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def get_recent_iocs(days \\ 7) when is_integer(days) and days > 0 do
    body = Jason.encode!(%{query: "get_iocs", days: min(days, 30)})
    headers = [{"Content-Type", "application/json"}]

    case http_post(@threatfox_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_threatfox_list_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Query ThreatFox for IOCs associated with a specific malware family.

  ## Examples

      iex> query_malware("Emotet")
      {:ok, [%{ioc: "...", ioc_type: "ip:port", ...}, ...]}
  """
  @spec query_malware(String.t(), pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def query_malware(malware_name, limit \\ 100) when is_binary(malware_name) do
    body = Jason.encode!(%{query: "malwareinfo", malware: malware_name, limit: min(limit, 1000)})
    headers = [{"Content-Type", "application/json"}]

    case http_post(@threatfox_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_threatfox_list_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  @doc """
  Query ThreatFox by tag.

  ## Examples

      iex> query_tag("cobalt-strike")
      {:ok, [%{ioc: "...", threat_type: "c2", ...}, ...]}
  """
  @spec query_tag(String.t(), pos_integer()) :: {:ok, [map()]} | {:error, term()}
  def query_tag(tag, limit \\ 100) when is_binary(tag) do
    body = Jason.encode!(%{query: "taginfo", tag: tag, limit: min(limit, 1000)})
    headers = [{"Content-Type", "application/json"}]

    case http_post(@threatfox_api, body, headers) do
      {:ok, %Finch.Response{status: 200, body: response_body}} ->
        parse_threatfox_list_response(response_body)

      {:ok, %Finch.Response{status: status}} ->
        {:error, {:http_error, status}}

      {:error, %Mint.TransportError{reason: reason}} ->
        {:error, reason}
    end
  end

  # ============================================================================
  # Response Parsers - MalwareBazaar
  # ============================================================================

  defp parse_malwarebazaar_hash_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "data" => [sample | _]}} ->
        {:ok, normalize_malwarebazaar_sample(sample)}

      {:ok, %{"query_status" => "hash_not_found"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => "no_results"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_malwarebazaar_list_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "data" => samples}} when is_list(samples) ->
        {:ok, Enum.map(samples, &normalize_malwarebazaar_sample/1)}

      {:ok, %{"query_status" => "no_results"}} ->
        {:ok, []}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_malwarebazaar_info_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "data" => [sample | _]}} ->
        info = normalize_malwarebazaar_sample(sample)

        # Add extended info
        extended = %{
          yara_rules: Map.get(sample, "yara_rules", []),
          vendor_intel: Map.get(sample, "vendor_intel", %{}),
          origin_country: Map.get(sample, "origin_country"),
          imphash: Map.get(sample, "imphash"),
          tlsh: Map.get(sample, "tlsh"),
          ssdeep: Map.get(sample, "ssdeep"),
          code_sign: Map.get(sample, "code_sign", [])
        }

        {:ok, Map.merge(info, extended)}

      {:ok, %{"query_status" => "hash_not_found"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp normalize_malwarebazaar_sample(sample) do
    %{
      sha256: Map.get(sample, "sha256_hash"),
      sha1: Map.get(sample, "sha1_hash"),
      md5: Map.get(sample, "md5_hash"),
      file_type: Map.get(sample, "file_type"),
      file_type_mime: Map.get(sample, "file_type_mime"),
      file_size: Map.get(sample, "file_size"),
      file_name: Map.get(sample, "file_name"),
      signature: Map.get(sample, "signature"),
      first_seen: Map.get(sample, "first_seen"),
      last_seen: Map.get(sample, "last_seen"),
      reporter: Map.get(sample, "reporter"),
      tags: Map.get(sample, "tags", []),
      delivery_method: Map.get(sample, "delivery_method"),
      intelligence: Map.get(sample, "intelligence", %{}),
      source: "malwarebazaar"
    }
  end

  # ============================================================================
  # Response Parsers - URLhaus
  # ============================================================================

  defp parse_urlhaus_url_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok"} = data} ->
        {:ok, normalize_urlhaus_url(data)}

      {:ok, %{"query_status" => "no_results"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_urlhaus_host_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "urls" => urls}} when is_list(urls) ->
        {:ok, Enum.map(urls, &normalize_urlhaus_url_entry/1)}

      {:ok, %{"query_status" => "no_results"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_urlhaus_recent_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "urls" => urls}} when is_list(urls) ->
        {:ok, Enum.map(urls, &normalize_urlhaus_url_entry/1)}

      {:ok, %{"urls" => urls}} when is_list(urls) ->
        {:ok, Enum.map(urls, &normalize_urlhaus_url_entry/1)}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_urlhaus_payload_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok"} = data} ->
        payload = %{
          sha256: Map.get(data, "sha256_hash"),
          md5: Map.get(data, "md5_hash"),
          file_type: Map.get(data, "file_type"),
          file_size: Map.get(data, "file_size"),
          signature: Map.get(data, "signature"),
          first_seen: Map.get(data, "firstseen"),
          url_count: Map.get(data, "url_count"),
          urls: Map.get(data, "urls", []) |> Enum.map(&normalize_urlhaus_url_entry/1),
          source: "urlhaus"
        }
        {:ok, payload}

      {:ok, %{"query_status" => "no_results"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp normalize_urlhaus_url(data) do
    %{
      id: Map.get(data, "id"),
      url: Map.get(data, "url"),
      url_status: Map.get(data, "url_status"),
      host: Map.get(data, "host"),
      date_added: Map.get(data, "date_added"),
      last_online: Map.get(data, "last_online"),
      threat: Map.get(data, "threat"),
      blacklists: Map.get(data, "blacklists", %{}),
      reporter: Map.get(data, "reporter"),
      larted: Map.get(data, "larted"),
      tags: Map.get(data, "tags", []),
      payloads: Map.get(data, "payloads", []) |> Enum.map(&normalize_urlhaus_payload/1),
      source: "urlhaus"
    }
  end

  defp normalize_urlhaus_url_entry(entry) do
    %{
      id: Map.get(entry, "id"),
      url: Map.get(entry, "url"),
      url_status: Map.get(entry, "url_status"),
      host: Map.get(entry, "host"),
      date_added: Map.get(entry, "dateadded") || Map.get(entry, "date_added"),
      threat: Map.get(entry, "threat"),
      tags: Map.get(entry, "tags", []),
      reporter: Map.get(entry, "reporter"),
      source: "urlhaus"
    }
  end

  defp normalize_urlhaus_payload(payload) do
    %{
      sha256: Map.get(payload, "sha256_hash"),
      file_type: Map.get(payload, "file_type"),
      file_size: Map.get(payload, "file_size"),
      signature: Map.get(payload, "signature"),
      first_seen: Map.get(payload, "firstseen"),
      vt_percent: Map.get(payload, "virustotal", %{}) |> Map.get("percent")
    }
  end

  # ============================================================================
  # Response Parsers - ThreatFox
  # ============================================================================

  defp parse_threatfox_ioc_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "data" => [ioc | _]}} ->
        {:ok, normalize_threatfox_ioc(ioc)}

      {:ok, %{"query_status" => "ok", "data" => []}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => "no_result"}} ->
        {:ok, :not_found}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp parse_threatfox_list_response(body) do
    case Jason.decode(body) do
      {:ok, %{"query_status" => "ok", "data" => iocs}} when is_list(iocs) ->
        {:ok, Enum.map(iocs, &normalize_threatfox_ioc/1)}

      {:ok, %{"query_status" => "no_result"}} ->
        {:ok, []}

      {:ok, %{"query_status" => status}} ->
        {:error, {:api_error, status}}

      {:error, reason} ->
        {:error, {:json_decode_error, reason}}
    end
  end

  defp normalize_threatfox_ioc(ioc) do
    %{
      id: Map.get(ioc, "id"),
      ioc: Map.get(ioc, "ioc"),
      ioc_type: Map.get(ioc, "ioc_type"),
      threat_type: Map.get(ioc, "threat_type"),
      threat_type_desc: Map.get(ioc, "threat_type_desc"),
      malware: Map.get(ioc, "malware"),
      malware_alias: Map.get(ioc, "malware_alias"),
      malware_printable: Map.get(ioc, "malware_printable"),
      malware_malpedia: Map.get(ioc, "malware_malpedia"),
      confidence_level: Map.get(ioc, "confidence_level"),
      first_seen: Map.get(ioc, "first_seen"),
      last_seen: Map.get(ioc, "last_seen"),
      reporter: Map.get(ioc, "reporter"),
      reference: Map.get(ioc, "reference"),
      tags: Map.get(ioc, "tags", []),
      source: "threatfox"
    }
  end

  # ============================================================================
  # HTTP Helpers
  # ============================================================================

  defp http_get(url, headers) do
    Finch.build(:get, url, headers) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout)
  end

  defp http_post(url, body, headers) do
    Finch.build(:post, url, headers, body) |> Finch.request(TamanduaServer.Finch, receive_timeout: @recv_timeout)
  end
end
