defmodule TamanduaServer.Connectors.VirusTotal do
  @moduledoc """
  VirusTotal connector for file/URL reputation and threat intelligence.

  Capabilities:
  - Query file hashes for malware verdicts
  - Submit files for scanning
  - URL reputation checks
  - Domain/IP reputation lookups
  - Pull VT Livehunt YARA rules
  """

  use TamanduaServer.Connectors.Behaviour
  require Logger

  alias TamanduaServer.Connectors.Helpers.{Auth, Retry, RateLimiter}

  defmodule State do
    @moduledoc false
    defstruct [:api_key, :base_url, :tier, :verify_ssl]
  end

  @impl true
  def metadata do
    %{
      name: "VirusTotal Connector",
      version: "1.0.0",
      type: :ioc_source,
      description: "Threat intelligence and file reputation from VirusTotal",
      author: "Tamandua Team",
      config_schema: %{
        required: [:api_key],
        properties: %{
          api_key: %{type: :string, min_length: 64},
          tier: %{type: :string, default: "free"},
          base_url: %{type: :string, format: :url, default: "https://www.virustotal.com/api/v3"},
          verify_ssl: %{type: :boolean, default: true}
        }
      }
    }
  end

  @impl true
  def init(config) do
    state = %State{
      api_key: config.api_key,
      base_url: Map.get(config, :base_url, "https://www.virustotal.com/api/v3"),
      tier: Map.get(config, :tier, "free"),
      verify_ssl: Map.get(config, :verify_ssl, true)
    }

    case test_connection(state) do
      :ok ->
        Logger.info("[VirusTotal Connector] Initialized successfully (tier: #{state.tier})")
        {:ok, state}

      {:error, reason} ->
        {:error, {:connection_failed, reason}}
    end
  end

  @impl true
  def start(_state) do
    Logger.info("[VirusTotal Connector] Started")
    :ok
  end

  @impl true
  def stop(_state) do
    Logger.info("[VirusTotal Connector] Stopped")
    :ok
  end

  @impl true
  def health(state) do
    case test_connection(state) do
      :ok ->
        {:ok, %{status: :healthy, tier: state.tier}}

      {:error, reason} ->
        {:error, {:unhealthy, reason}}
    end
  end

  @impl true
  def handle_inbound(event, state) do
    # Query VirusTotal for hash/URL/domain/IP reputation
    case event.query_type do
      "hash" -> query_file_hash(event.value, state)
      "url" -> query_url(event.value, state)
      "domain" -> query_domain(event.value, state)
      "ip" -> query_ip(event.value, state)
      _ -> {:error, :unsupported_query_type}
    end
  end

  @impl true
  def transform_inbound(event) do
    %{
      type: "reputation_check",
      source: "virustotal",
      timestamp: DateTime.utc_now(),
      data: event
    }
  end

  # Private Functions

  defp test_connection(state) do
    # Test with a simple quota check
    url = "#{state.base_url}/users/current"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "x-apikey")]

    Retry.with_backoff(fn ->
      case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
        {:ok, %{status: 200}} -> {:ok, :connected}
        {:ok, %{status: 401}} -> {:error, :invalid_api_key}
        {:ok, %{status: status}} -> {:error, {:http_error, status}}
        {:error, reason} -> {:error, reason}
      end
    end, max_attempts: 2)
  end

  defp query_file_hash(hash, state) do
    url = "#{state.base_url}/files/#{hash}"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "x-apikey")]

    # Rate limits vary by tier:
    # Free: 4 req/min, Premium: 500 req/min, Enterprise: 1000 req/min
    rate_limit = tier_rate_limit(state.tier)

    case RateLimiter.check_rate("virustotal:api", limit: rate_limit, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} ->
              result = parse_file_report(body, hash)
              {:ok, result}

            {:ok, %{status: 404}} ->
              {:ok, %{found: false, hash: hash}}

            {:ok, %{status: 429}} ->
              {:error, :rate_limited}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end, max_attempts: 2)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp query_url(url_to_check, state) do
    # URL needs to be base64 encoded (no padding)
    url_id = Base.url_encode64(url_to_check, padding: false)
    url = "#{state.base_url}/urls/#{url_id}"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "x-apikey")]

    rate_limit = tier_rate_limit(state.tier)

    case RateLimiter.check_rate("virustotal:api", limit: rate_limit, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} ->
              result = parse_url_report(body, url_to_check)
              {:ok, result}

            {:ok, %{status: 404}} ->
              {:ok, %{found: false, url: url_to_check}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end, max_attempts: 2)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp query_domain(domain, state) do
    url = "#{state.base_url}/domains/#{domain}"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "x-apikey")]

    rate_limit = tier_rate_limit(state.tier)

    case RateLimiter.check_rate("virustotal:api", limit: rate_limit, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} ->
              result = parse_domain_report(body, domain)
              {:ok, result}

            {:ok, %{status: 404}} ->
              {:ok, %{found: false, domain: domain}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end, max_attempts: 2)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp query_ip(ip, state) do
    url = "#{state.base_url}/ip_addresses/#{ip}"
    headers = [Auth.build_api_key_header(state.api_key, prefix: "x-apikey")]

    rate_limit = tier_rate_limit(state.tier)

    case RateLimiter.check_rate("virustotal:api", limit: rate_limit, window: 60) do
      :ok ->
        Retry.with_backoff(fn ->
          case Req.get(url, headers: headers, connect_options: [verify: state.verify_ssl]) do
            {:ok, %{status: 200, body: body}} ->
              result = parse_ip_report(body, ip)
              {:ok, result}

            {:ok, %{status: 404}} ->
              {:ok, %{found: false, ip: ip}}

            {:ok, %{status: status}} ->
              {:error, {:http_error, status}}

            {:error, reason} ->
              {:error, reason}
          end
        end, max_attempts: 2)

      {:error, {:rate_limited, wait_time}} ->
        {:error, {:rate_limited, wait_time}}
    end
  end

  defp parse_file_report(body, hash) do
    data = body["data"]
    attrs = data["attributes"]
    stats = attrs["last_analysis_stats"]

    malicious = stats["malicious"] || 0
    suspicious = stats["suspicious"] || 0
    total = malicious + suspicious + (stats["undetected"] || 0) + (stats["harmless"] || 0)

    %{
      found: true,
      hash: hash,
      malicious_count: malicious,
      suspicious_count: suspicious,
      total_engines: total,
      verdict: if(malicious > 5, do: "malicious", else: "clean"),
      severity: malicious_count_to_severity(malicious),
      names: attrs["names"] || [],
      file_type: attrs["type_description"],
      size: attrs["size"],
      first_seen: parse_timestamp(attrs["first_submission_date"]),
      last_seen: parse_timestamp(attrs["last_analysis_date"]),
      metadata: %{
        sha256: attrs["sha256"],
        md5: attrs["md5"],
        sha1: attrs["sha1"],
        tags: attrs["tags"] || []
      }
    }
  end

  defp parse_url_report(body, url) do
    data = body["data"]
    attrs = data["attributes"]
    stats = attrs["last_analysis_stats"]

    malicious = stats["malicious"] || 0

    %{
      found: true,
      url: url,
      malicious_count: malicious,
      verdict: if(malicious > 2, do: "malicious", else: "clean"),
      severity: malicious_count_to_severity(malicious),
      categories: attrs["categories"] || %{},
      last_seen: parse_timestamp(attrs["last_analysis_date"])
    }
  end

  defp parse_domain_report(body, domain) do
    data = body["data"]
    attrs = data["attributes"]
    stats = attrs["last_analysis_stats"] || %{}

    malicious = stats["malicious"] || 0

    %{
      found: true,
      domain: domain,
      malicious_count: malicious,
      verdict: if(malicious > 2, do: "malicious", else: "clean"),
      severity: malicious_count_to_severity(malicious),
      reputation: attrs["reputation"] || 0,
      categories: attrs["categories"] || %{},
      whois: attrs["whois"]
    }
  end

  defp parse_ip_report(body, ip) do
    data = body["data"]
    attrs = data["attributes"]
    stats = attrs["last_analysis_stats"] || %{}

    malicious = stats["malicious"] || 0

    %{
      found: true,
      ip: ip,
      malicious_count: malicious,
      verdict: if(malicious > 2, do: "malicious", else: "clean"),
      severity: malicious_count_to_severity(malicious),
      reputation: attrs["reputation"] || 0,
      country: attrs["country"],
      asn: attrs["asn"],
      as_owner: attrs["as_owner"]
    }
  end

  defp malicious_count_to_severity(count) do
    cond do
      count >= 30 -> "critical"
      count >= 15 -> "high"
      count >= 5 -> "medium"
      count >= 1 -> "low"
      true -> "info"
    end
  end

  defp tier_rate_limit(tier) do
    case tier do
      "free" -> 4
      "premium" -> 500
      "enterprise" -> 1000
      _ -> 4
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(ts) when is_integer(ts), do: DateTime.from_unix!(ts)
  defp parse_timestamp(_), do: nil
end
