defmodule TamanduaServer.DarkWeb.Feeds.Flashpoint do
  @moduledoc """
  Integration with Flashpoint threat intelligence platform.

  Flashpoint provides comprehensive intelligence from dark web forums, marketplaces,
  illicit communities, and underground sources.

  ## Configuration

  Set environment variable:
      export FLASHPOINT_API_KEY=your-api-key

  ## Features

  - Forum posts and discussions
  - Marketplace listings
  - Breach data
  - Compromised credentials
  - Vulnerability intelligence
  - Threat actor tracking
  - IOC enrichment

  ## API Documentation

  https://docs.flashpoint.io/
  """

  require Logger
  alias TamanduaServer.Cache

  @base_url "https://api.flashpoint.io"

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Search for compromised credentials.

  ## Parameters

    - `opts` - Options:
      - `:query` - Email, domain, or keyword
      - `:size` - Number of results (default: 50)

  ## Example

      iex> search_credentials(query: "example.com")
      {:ok, %{
        "hits" => [
          %{
            "email" => "user@example.com",
            "breach" => %{
              "title" => "Breach name",
              "created_at" => "2024-01-15T10:00:00Z"
            },
            "password" => %{
              "plain" => "password123",
              "hash" => %{"algorithm" => "md5", "value" => "..."}
            }
          }
        ],
        "total" => 123
      }}
  """
  @spec search_credentials(keyword()) :: {:ok, map()} | {:error, term()}
  def search_credentials(opts \\ []) do
    query = Keyword.get(opts, :query, "")
    size = Keyword.get(opts, :size, 50)

    url = "#{@base_url}/sources/v2/breaches"

    params = %{
      query: query,
      size: size
    }

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Search forum posts and discussions.

  ## Parameters

    - `query` - Search query
    - `opts` - Options:
      - `:size` - Number of results (default: 50)
      - `:since` - Start date (ISO8601)

  ## Example

      iex> search_forums("healthcare ransomware", size: 10)
      {:ok, %{
        "hits" => [
          %{
            "title" => "...",
            "body" => "...",
            "author" => "threat_actor_123",
            "site" => "Dark Forum",
            "published_at" => "2024-01-15T10:00:00Z",
            ...
          }
        ]
      }}
  """
  @spec search_forums(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_forums(query, opts \\ []) do
    size = Keyword.get(opts, :size, 50)
    since = Keyword.get(opts, :since)

    url = "#{@base_url}/sources/v2/forums/posts"

    params =
      %{
        query: query,
        size: size
      }
      |> maybe_add_param(:since, since)

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Search marketplace listings (credential marketplaces, exploit sales, etc.).

  ## Parameters

    - `query` - Search query
    - `opts` - Options:
      - `:size` - Number of results (default: 50)

  ## Example

      iex> search_marketplaces("database access")
      {:ok, %{
        "hits" => [
          %{
            "title" => "Database credentials for sale",
            "price" => "$500",
            "description" => "...",
            "vendor" => "vendor_123",
            "published_at" => "2024-01-15T10:00:00Z",
            ...
          }
        ]
      }}
  """
  @spec search_marketplaces(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_marketplaces(query, opts \\ []) do
    size = Keyword.get(opts, :size, 50)

    url = "#{@base_url}/sources/v2/marketplaces/listings"

    params = %{
      query: query,
      size: size
    }

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Search for threat actors.

  ## Example

      iex> search_actors("lockbit")
      {:ok, %{
        "hits" => [
          %{
            "name" => "LockBit",
            "aliases" => ["LockBit 2.0"],
            "description" => "...",
            "activity" => [...]
          }
        ]
      }}
  """
  @spec search_actors(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_actors(query, opts \\ []) do
    size = Keyword.get(opts, :size, 50)

    url = "#{@base_url}/threat-actors/v1/search"

    params = %{
      query: query,
      size: size
    }

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Get IOC enrichment (indicators of compromise).

  ## Parameters

    - `ioc` - IOC value (IP, domain, hash, etc.)
    - `ioc_type` - Type: ip, domain, url, email, hash

  ## Example

      iex> enrich_ioc("evil.com", "domain")
      {:ok, %{
        "ioc" => "evil.com",
        "type" => "domain",
        "first_seen" => "2024-01-01T00:00:00Z",
        "last_seen" => "2024-01-15T10:00:00Z",
        "context" => [...],
        "related_malware" => [...],
        "threat_score" => 85
      }}
  """
  @spec enrich_ioc(String.t(), String.t()) :: {:ok, map()} | {:error, term()}
  def enrich_ioc(ioc, ioc_type) do
    cache_key = "flashpoint:ioc:#{ioc_type}:#{ioc}"
    cache_ttl = :timer.hours(6)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/indicators/v1/simple/#{ioc_type}/#{URI.encode(ioc)}"

        case http_get(url) do
          {:ok, enrichment} ->
            Cache.put(cache_key, enrichment, cache_ttl)
            {:ok, enrichment}

          {:error, :not_found} ->
            # Not found in Flashpoint
            {:ok, %{found: false}}

          error ->
            error
        end
    end
  end

  @doc """
  Search for vulnerabilities and exploits.

  ## Parameters

    - `query` - CVE ID or keyword search
    - `opts` - Options:
      - `:size` - Number of results (default: 50)

  ## Example

      iex> search_vulnerabilities("CVE-2024-1234")
      {:ok, %{
        "hits" => [
          %{
            "cve" => "CVE-2024-1234",
            "title" => "...",
            "description" => "...",
            "exploit_available" => true,
            "exploit_source" => "dark web forum",
            ...
          }
        ]
      }}
  """
  @spec search_vulnerabilities(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_vulnerabilities(query, opts \\ []) do
    size = Keyword.get(opts, :size, 50)

    url = "#{@base_url}/vulnerabilities/v1/search"

    params = %{
      query: query,
      size: size
    }

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Get reports and intelligence reports.

  ## Parameters

    - `opts` - Options:
      - `:query` - Search query
      - `:size` - Number of results (default: 50)
      - `:since` - Start date (ISO8601)

  ## Example

      iex> get_reports(query: "ransomware healthcare")
      {:ok, %{
        "hits" => [
          %{
            "title" => "Ransomware Report",
            "summary" => "...",
            "published_at" => "2024-01-15",
            "tags" => ["ransomware", "healthcare"],
            ...
          }
        ]
      }}
  """
  @spec get_reports(keyword()) :: {:ok, map()} | {:error, term()}
  def get_reports(opts \\ []) do
    query = Keyword.get(opts, :query)
    size = Keyword.get(opts, :size, 50)
    since = Keyword.get(opts, :since)

    url = "#{@base_url}/finished-intelligence/v1/reports"

    params =
      %{size: size}
      |> maybe_add_param(:query, query)
      |> maybe_add_param(:since, since)

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  @doc """
  Search for data leaks.

  ## Parameters

    - `query` - Search query (company name, email domain, etc.)
    - `opts` - Options:
      - `:size` - Number of results (default: 50)

  ## Example

      iex> search_data_leaks("example.com")
      {:ok, %{
        "hits" => [
          %{
            "title" => "Example.com database leak",
            "size" => "10GB",
            "record_count" => 1000000,
            "data_types" => ["emails", "passwords", "credit_cards"],
            "first_seen" => "2024-01-15",
            ...
          }
        ]
      }}
  """
  @spec search_data_leaks(String.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def search_data_leaks(query, opts \\ []) do
    size = Keyword.get(opts, :size, 50)

    url = "#{@base_url}/sources/v2/leaks"

    params = %{
      query: query,
      size: size
    }

    query_string = URI.encode_query(params)
    full_url = "#{url}?#{query_string}"

    with {:ok, response} <- http_get(full_url) do
      {:ok, response}
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp http_get(url) do
    api_key = System.get_env("FLASHPOINT_API_KEY")

    if !api_key do
      Logger.warning("[Flashpoint] API key not configured")
      {:error, :no_api_key}
    else
      headers = [
        {"Authorization", "Bearer #{api_key}"},
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
          Logger.error("[Flashpoint] Authentication failed")
          {:error, :authentication_failed}

        {:ok, %{status_code: 403}} ->
          Logger.error("[Flashpoint] Access forbidden")
          {:error, :access_forbidden}

        {:ok, %{status_code: 404}} ->
          {:error, :not_found}

        {:ok, %{status_code: 429}} ->
          {:error, :rate_limited}

        {:ok, %{status_code: status_code, body: body}} ->
          Logger.warning("[Flashpoint] Unexpected status #{status_code}: #{body}")
          {:error, {:http_error, status_code, body}}

        {:error, reason} ->
          {:error, {:http_error, reason}}
      end
    end
  end

  defp maybe_add_param(params, _key, nil), do: params
  defp maybe_add_param(params, key, value), do: Map.put(params, key, value)
end
