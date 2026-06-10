defmodule TamanduaServer.DarkWeb.Feeds.Intel471 do
  @moduledoc """
  Integration with Intel 471 Titan threat intelligence platform.

  Intel 471 provides underground intelligence from dark web forums, marketplaces,
  ransomware groups, and threat actor communications.

  ## Configuration

  Set environment variables:
      export INTEL471_API_KEY=your-api-key
      export INTEL471_API_USER=your-username

  ## Features

  - Adversary intelligence (threat actors, groups)
  - Indicators (IPs, domains, hashes, emails)
  - Reports (ransomware negotiations, data leaks)
  - Credentials (compromised credentials marketplace)
  - Malware intelligence
  - Vulnerability intelligence

  ## API Documentation

  https://api.intel471.com/v1/docs
  """

  require Logger
  alias TamanduaServer.Cache

  @base_url "https://api.intel471.com/v1"

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Search for adversary intelligence (threat actors).

  ## Parameters

    - `query` - Search query (threat actor name, alias, etc.)
    - `opts` - Options:
      - `:count` - Number of results (default: 50)
      - `:from` - Start date (ISO8601)
      - `:until` - End date (ISO8601)

  ## Example

      iex> search_adversaries("lockbit")
      {:ok, %{
        "adversaries" => [
          %{
            "uid" => "abc123",
            "name" => "LockBit",
            "aliases" => ["LockBit 2.0", "LockBit 3.0"],
            "description" => "...",
            "motivation" => "financial",
            "sophistication" => "high",
            ...
          }
        ],
        "total_count" => 1
      }}
  """
  @spec search_adversaries(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_adversaries(query, opts \\ []) do
    count = Keyword.get(opts, :count, 50)
    from_date = Keyword.get(opts, :from)
    until_date = Keyword.get(opts, :until)

    params =
      %{
        adversary: query,
        count: count
      }
      |> maybe_add_param(:from, from_date)
      |> maybe_add_param(:until, until_date)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/adversaries?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  @doc """
  Get detailed information about a specific adversary.

  ## Example

      iex> get_adversary("abc123")
      {:ok, %{
        "uid" => "abc123",
        "name" => "LockBit",
        "aliases" => ["LockBit 2.0"],
        "description" => "...",
        "target_industries" => ["healthcare", "finance"],
        "ttps" => ["T1486", "T1490"],
        ...
      }}
  """
  @spec get_adversary(String.t()) :: {:ok, map()} | {:error, term()}
  def get_adversary(uid) do
    cache_key = "intel471:adversary:#{uid}"
    cache_ttl = :timer.hours(24)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/adversaries/#{uid}"

        case http_get(url) do
          {:ok, adversary} ->
            Cache.put(cache_key, adversary, cache_ttl)
            {:ok, adversary}

          error ->
            error
        end
    end
  end

  @doc """
  Search for indicators of compromise.

  ## Parameters

    - `opts` - Options:
      - `:ioc` - IOC value to search for
      - `:type` - IOC type (ip, domain, url, email, hash)
      - `:count` - Number of results (default: 50)

  ## Example

      iex> search_indicators(ioc: "evil.com", type: "domain")
      {:ok, %{
        "indicators" => [
          %{
            "uid" => "xyz789",
            "value" => "evil.com",
            "type" => "domain",
            "last_seen" => "2024-01-15T10:00:00Z",
            "confidence" => "high",
            "context" => "...",
            ...
          }
        ]
      }}
  """
  @spec search_indicators(keyword()) :: {:ok, map()} | {:error, term()}
  def search_indicators(opts \\ []) do
    ioc = Keyword.get(opts, :ioc)
    type = Keyword.get(opts, :type)
    count = Keyword.get(opts, :count, 50)

    params =
      %{count: count}
      |> maybe_add_param(:indicator, ioc)
      |> maybe_add_param(:indicatorType, type)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/indicators?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  @doc """
  Search for reports (ransomware negotiations, data leaks, etc.).

  ## Parameters

    - `opts` - Options:
      - `:text` - Search text
      - `:report_type` - Type: breach, ransomware, malware, vulnerability
      - `:count` - Number of results (default: 50)

  ## Example

      iex> search_reports(text: "healthcare data leak", report_type: "breach")
      {:ok, %{
        "reports" => [
          %{
            "uid" => "report123",
            "title" => "Healthcare breach",
            "subject" => "...",
            "released" => "2024-01-15T10:00:00Z",
            "report_type" => "breach",
            "victims" => ["Hospital X"],
            "adversaries" => ["LockBit"],
            ...
          }
        ]
      }}
  """
  @spec search_reports(keyword()) :: {:ok, map()} | {:error, term()}
  def search_reports(opts \\ []) do
    text = Keyword.get(opts, :text)
    report_type = Keyword.get(opts, :report_type)
    count = Keyword.get(opts, :count, 50)

    params =
      %{count: count}
      |> maybe_add_param(:text, text)
      |> maybe_add_param(:reportType, report_type)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/reports?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  @doc """
  Get a specific report by UID.
  """
  @spec get_report(String.t()) :: {:ok, map()} | {:error, term()}
  def get_report(uid) do
    cache_key = "intel471:report:#{uid}"
    cache_ttl = :timer.hours(24)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/reports/#{uid}"

        case http_get(url) do
          {:ok, report} ->
            Cache.put(cache_key, report, cache_ttl)
            {:ok, report}

          error ->
            error
        end
    end
  end

  @doc """
  Search for compromised credentials.

  ## Parameters

    - `opts` - Options:
      - `:email` - Email address
      - `:domain` - Email domain
      - `:count` - Number of results (default: 50)

  ## Example

      iex> search_credentials(domain: "example.com")
      {:ok, %{
        "credentials" => [
          %{
            "uid" => "cred123",
            "email" => "user@example.com",
            "password" => "hashed_or_encrypted",
            "breach_date" => "2023-12-01",
            "source" => "Dark web marketplace",
            ...
          }
        ]
      }}
  """
  @spec search_credentials(keyword()) :: {:ok, map()} | {:error, term()}
  def search_credentials(opts \\ []) do
    email = Keyword.get(opts, :email)
    domain = Keyword.get(opts, :domain)
    count = Keyword.get(opts, :count, 50)

    params =
      %{count: count}
      |> maybe_add_param(:email, email)
      |> maybe_add_param(:domain, domain)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/credentials?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  @doc """
  Search for malware intelligence.

  ## Parameters

    - `opts` - Options:
      - `:malware_family` - Malware family name
      - `:count` - Number of results (default: 50)

  ## Example

      iex> search_malware(malware_family: "emotet")
      {:ok, %{
        "malware" => [...]
      }}
  """
  @spec search_malware(keyword()) :: {:ok, map()} | {:error, term()}
  def search_malware(opts \\ []) do
    malware_family = Keyword.get(opts, :malware_family)
    count = Keyword.get(opts, :count, 50)

    params =
      %{count: count}
      |> maybe_add_param(:malwareFamily, malware_family)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/malware?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  @doc """
  Search for vulnerability intelligence (exploits in the wild).

  ## Parameters

    - `opts` - Options:
      - `:cve` - CVE identifier
      - `:count` - Number of results (default: 50)

  ## Example

      iex> search_vulnerabilities(cve: "CVE-2024-1234")
      {:ok, %{
        "vulnerabilities" => [...]
      }}
  """
  @spec search_vulnerabilities(keyword()) :: {:ok, map()} | {:error, term()}
  def search_vulnerabilities(opts \\ []) do
    cve = Keyword.get(opts, :cve)
    count = Keyword.get(opts, :count, 50)

    params =
      %{count: count}
      |> maybe_add_param(:cve, cve)

    query_string = URI.encode_query(params)
    url = "#{@base_url}/vulnerabilities?#{query_string}"

    with {:ok, response} <- http_get(url) do
      {:ok, response}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp http_get(url) do
    api_key = System.get_env("INTEL471_API_KEY")
    api_user = System.get_env("INTEL471_API_USER")

    if !api_key or !api_user do
      Logger.warning("[Intel471] API credentials not configured")
      {:error, :no_api_credentials}
    else
      # Intel 471 uses Basic Auth
      auth = Base.encode64("#{api_user}:#{api_key}")

      headers = [
        {"Authorization", "Basic #{auth}"},
        {"Content-Type", "application/json"},
        {"User-Agent", "Tamandua-EDR"}
      ]

      case HTTPoison.get(url, headers, timeout: 30_000, recv_timeout: 30_000) do
        {:ok, %{status_code: 200, body: body}} ->
          case Jason.decode(body) do
            {:ok, data} -> {:ok, data}
            {:error, reason} -> {:error, {:json_decode_error, reason}}
          end

        {:ok, %{status_code: 401}} ->
          Logger.error("[Intel471] Authentication failed")
          {:error, :authentication_failed}

        {:ok, %{status_code: 403}} ->
          Logger.error("[Intel471] Access forbidden")
          {:error, :access_forbidden}

        {:ok, %{status_code: 404}} ->
          {:error, :not_found}

        {:ok, %{status_code: 429}} ->
          {:error, :rate_limited}

        {:ok, %{status_code: status_code, body: body}} ->
          Logger.warning("[Intel471] Unexpected status #{status_code}: #{body}")
          {:error, {:http_error, status_code, body}}

        {:error, reason} ->
          {:error, {:http_error, reason}}
      end
    end
  end

  defp maybe_add_param(params, _key, nil), do: params
  defp maybe_add_param(params, key, value), do: Map.put(params, key, value)
end
