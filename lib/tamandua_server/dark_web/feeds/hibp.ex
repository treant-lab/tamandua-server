defmodule TamanduaServer.DarkWeb.Feeds.HIBP do
  @moduledoc """
  Integration with Have I Been Pwned (HIBP) API.

  API Documentation: https://haveibeenpwned.com/API/v3

  ## Configuration

  Set environment variable:
      export HIBP_API_KEY=your-api-key

  ## Features

  - Breach discovery (all breaches)
  - Email compromise check
  - Domain breach check
  - Password exposure check (Pwned Passwords)

  ## Rate Limits

  - 1 request every 1500ms (rate limited by HIBP)
  - Use API key for higher limits
  """

  require Logger
  alias TamanduaServer.Cache

  @base_url "https://haveibeenpwned.com/api/v3"
  @rate_limit_ms 1500

  # ============================================================================
  # Client API
  # ============================================================================

  @doc """
  Fetch all breaches from HIBP.

  Returns a list of breach records.

  ## Example

      iex> get_all_breaches()
      {:ok, [
        %{
          "Name" => "Adobe",
          "Title" => "Adobe",
          "Domain" => "adobe.com",
          "BreachDate" => "2013-10-04",
          "AddedDate" => "2013-12-04T00:00:00Z",
          "ModifiedDate" => "2013-12-04T00:00:00Z",
          "PwnCount" => 152445165,
          "Description" => "...",
          "DataClasses" => ["Email addresses", "Password hints", "Passwords", "Usernames"],
          "IsVerified" => true,
          "IsFabricated" => false,
          "IsSensitive" => false,
          "IsRetired" => false,
          "IsSpamList" => false,
          "IsMalware" => false,
          "LogoPath" => "https://..."
        },
        ...
      ]}
  """
  @spec get_all_breaches() :: {:ok, list(map())} | {:error, term()}
  def get_all_breaches do
    cache_key = "hibp:all_breaches"
    cache_ttl = :timer.hours(24)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        Logger.debug("[HIBP] Using cached breaches list")
        {:ok, cached}

      _ ->
        url = "#{@base_url}/breaches"

        case http_get(url) do
          {:ok, breaches} when is_list(breaches) ->
            Cache.put(cache_key, breaches, cache_ttl)
            {:ok, breaches}

          {:error, reason} = error ->
            Logger.error("[HIBP] Failed to fetch breaches: #{inspect(reason)}")
            error
        end
    end
  end

  @doc """
  Check if an email address has been compromised.

  ## Parameters

    - `email` - Email address to check
    - `opts` - Options:
      - `:truncate_response` - Return only breach names (default: false)
      - `:include_unverified` - Include unverified breaches (default: true)

  ## Examples

      iex> check_email("test@example.com")
      {:ok, [
        %{
          "Name" => "Adobe",
          "Title" => "Adobe",
          ...
        }
      ]}

      iex> check_email("clean@example.com")
      {:ok, :not_found}
  """
  @spec check_email(String.t(), keyword()) :: {:ok, list(map()) | :not_found} | {:error, term()}
  def check_email(email, opts \\ []) when is_binary(email) do
    truncate = Keyword.get(opts, :truncate_response, false)
    include_unverified = Keyword.get(opts, :include_unverified, true)

    cache_key = "hibp:email:#{email}"
    cache_ttl = :timer.hours(6)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        query_params =
          URI.encode_query(
            truncateResponse: truncate,
            includeUnverified: include_unverified
          )

        url = "#{@base_url}/breachedaccount/#{URI.encode(email)}?#{query_params}"

        # Rate limit
        :timer.sleep(@rate_limit_ms)

        case http_get(url) do
          {:ok, breaches} when is_list(breaches) ->
            Cache.put(cache_key, breaches, cache_ttl)
            {:ok, breaches}

          {:error, %{"statusCode" => 404}} ->
            # Not found = good news
            Cache.put(cache_key, :not_found, cache_ttl)
            {:ok, :not_found}

          {:error, reason} = error ->
            Logger.error("[HIBP] Failed to check email #{email}: #{inspect(reason)}")
            error
        end
    end
  end

  @doc """
  Check if a domain has had breaches.

  ## Example

      iex> check_domain("adobe.com")
      {:ok, [
        %{"Name" => "Adobe", ...}
      ]}
  """
  @spec check_domain(String.t()) :: {:ok, list(map()) | :not_found} | {:error, term()}
  def check_domain(domain) when is_binary(domain) do
    cache_key = "hibp:domain:#{domain}"
    cache_ttl = :timer.hours(24)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/breaches?domain=#{URI.encode(domain)}"

        case http_get(url) do
          {:ok, breaches} when is_list(breaches) and length(breaches) > 0 ->
            Cache.put(cache_key, breaches, cache_ttl)
            {:ok, breaches}

          {:ok, []} ->
            Cache.put(cache_key, :not_found, cache_ttl)
            {:ok, :not_found}

          {:error, reason} = error ->
            Logger.error("[HIBP] Failed to check domain #{domain}: #{inspect(reason)}")
            error
        end
    end
  end

  @doc """
  Check if a password has been exposed in data breaches.

  Uses k-anonymity model - only first 5 chars of SHA-1 hash are sent.

  ## Example

      iex> check_password("password123")
      {:ok, %{found: true, occurrences: 123456}}

      iex> check_password("veryStrongP@ssw0rd!")
      {:ok, %{found: false, occurrences: 0}}
  """
  @spec check_password(String.t()) :: {:ok, map()} | {:error, term()}
  def check_password(password) when is_binary(password) do
    # SHA-1 hash of password
    hash =
      :crypto.hash(:sha, password)
      |> Base.encode16()

    # Split into prefix (first 5 chars) and suffix
    prefix = String.slice(hash, 0, 5)
    suffix = String.slice(hash, 5..-1//1)

    url = "https://api.pwnedpasswords.com/range/#{prefix}"

    case http_get(url, [], parse_json: false) do
      {:ok, body} when is_binary(body) ->
        # Parse response - each line is "SUFFIX:COUNT"
        occurrences =
          body
          |> String.split("\r\n")
          |> Enum.find_value(0, fn line ->
            case String.split(line, ":") do
              [^suffix, count] -> String.to_integer(count)
              _ -> false
            end
          end)

        result = %{
          found: occurrences > 0,
          occurrences: occurrences
        }

        {:ok, result}

      {:error, reason} = error ->
        Logger.error("[HIBP] Failed to check password: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Get details for a specific breach by name.

  ## Example

      iex> get_breach("Adobe")
      {:ok, %{
        "Name" => "Adobe",
        "Title" => "Adobe",
        ...
      }}
  """
  @spec get_breach(String.t()) :: {:ok, map()} | {:error, term()}
  def get_breach(breach_name) when is_binary(breach_name) do
    cache_key = "hibp:breach:#{breach_name}"
    cache_ttl = :timer.hours(24)

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/breach/#{URI.encode(breach_name)}"

        case http_get(url) do
          {:ok, breach} when is_map(breach) ->
            Cache.put(cache_key, breach, cache_ttl)
            {:ok, breach}

          {:error, reason} = error ->
            Logger.error("[HIBP] Failed to get breach #{breach_name}: #{inspect(reason)}")
            error
        end
    end
  end

  @doc """
  Get data classes (types of data exposed).

  ## Example

      iex> get_data_classes()
      {:ok, ["Account balances", "Age groups", "Ages", ...]}
  """
  @spec get_data_classes() :: {:ok, list(String.t())} | {:error, term()}
  def get_data_classes do
    cache_key = "hibp:data_classes"
    cache_ttl = :timer.hours(168) # 1 week

    case Cache.get(cache_key) do
      {:ok, cached} ->
        {:ok, cached}

      _ ->
        url = "#{@base_url}/dataclasses"

        case http_get(url) do
          {:ok, classes} when is_list(classes) ->
            Cache.put(cache_key, classes, cache_ttl)
            {:ok, classes}

          {:error, reason} = error ->
            Logger.error("[HIBP] Failed to get data classes: #{inspect(reason)}")
            error
        end
    end
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp http_get(url, headers \\ [], opts \\ []) do
    parse_json = Keyword.get(opts, :parse_json, true)
    api_key = System.get_env("HIBP_API_KEY")

    # Add API key header if available
    headers =
      if api_key do
        [{"hibp-api-key", api_key} | headers]
      else
        headers
      end

    # Add User-Agent (required by HIBP API)
    headers = [
      {"User-Agent", "Tamandua-EDR"}
      | headers
    ]

    case HTTPoison.get(url, headers, timeout: 30_000, recv_timeout: 30_000) do
      {:ok, %{status_code: 200, body: body}} ->
        if parse_json do
          case Jason.decode(body) do
            {:ok, data} -> {:ok, data}
            {:error, reason} -> {:error, {:json_decode_error, reason}}
          end
        else
          {:ok, body}
        end

      {:ok, %{status_code: 404}} ->
        {:error, %{"statusCode" => 404, "message" => "Not found"}}

      {:ok, %{status_code: 429}} ->
        {:error, :rate_limited}

      {:ok, %{status_code: status_code, body: body}} ->
        Logger.warning("[HIBP] Unexpected status #{status_code}: #{body}")
        {:error, {:http_error, status_code, body}}

      {:error, reason} ->
        {:error, {:http_error, reason}}
    end
  end
end
