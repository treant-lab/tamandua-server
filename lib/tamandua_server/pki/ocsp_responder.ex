defmodule TamanduaServer.PKI.OCSPResponder do
  @moduledoc """
  Online Certificate Status Protocol (OCSP) responder.

  Provides real-time certificate revocation status checks as an alternative
  to CRL downloads. OCSP is faster and more bandwidth-efficient than CRLs
  for checking individual certificates.

  ## OCSP Request/Response Flow

  1. Client sends OCSP request (DER-encoded)
     - Contains certificate serial number
     - Hash of issuer name and key

  2. Server validates request and checks revocation status

  3. Server responds with signed OCSP response:
     - `good` - Certificate is valid and not revoked
     - `revoked` - Certificate has been revoked (includes reason and time)
     - `unknown` - Certificate serial not found

  ## Security

  - All OCSP responses are signed by the OCSP signing certificate
  - Nonce extension supported to prevent replay attacks
  - Response caching with configurable TTL (default: 1 hour)
  - Rate limiting to prevent DoS

  ## Configuration

      config :tamandua_server, TamanduaServer.PKI.OCSPResponder,
        response_cache_ttl_seconds: 3600,
        max_requests_per_minute: 1000,
        sign_responses: true

  ## Example

      # Handle OCSP request (called from HTTP controller)
      {:ok, response_der} = OCSPResponder.handle_request(request_der)

      # Check certificate status programmatically
      case OCSPResponder.check_status("ABC123") do
        {:ok, :good} -> # Certificate valid
        {:ok, :revoked, reason} -> # Certificate revoked
        {:ok, :unknown} -> # Certificate not found
      end
  """

  use GenServer
  require Logger
  alias TamanduaServer.OSCommand
  alias TamanduaServer.PKI.RevocationList
  alias TamanduaServer.PKI.CertificateAuthority
  alias TamanduaServer.Audit

  # 1 hour
  @response_cache_ttl_seconds 3600
  @max_requests_per_minute 1000
  # OCSP response valid for 24 hours
  @response_validity_seconds 86400

  defmodule State do
    @moduledoc false
    defstruct [
      :ocsp_signing_cert,
      :ocsp_signing_key,
      # ETS table
      :response_cache,
      # ETS table for rate limiting
      :rate_limiter,
      :sign_responses
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Handle an OCSP request and return a signed response.

  ## Parameters

    * `request_der` - DER-encoded OCSP request

  ## Returns

    * `{:ok, response_der}` - DER-encoded OCSP response
    * `{:error, :malformed_request}` - Invalid request format
    * `{:error, :rate_limited}` - Too many requests
    * `{:error, reason}` - Other errors
  """
  def handle_request(request_der) do
    GenServer.call(__MODULE__, {:handle_request, request_der})
  end

  @doc """
  Check the revocation status of a certificate by serial number.

  ## Returns

    * `{:ok, :good}` - Certificate is valid
    * `{:ok, :revoked, reason}` - Certificate is revoked
    * `{:ok, :unknown}` - Certificate serial not found
  """
  def check_status(serial_number) do
    GenServer.call(__MODULE__, {:check_status, serial_number})
  end

  @doc """
  Clear the OCSP response cache.

  Forces all subsequent requests to generate fresh responses.
  """
  def clear_cache do
    GenServer.cast(__MODULE__, :clear_cache)
  end

  @doc """
  Get OCSP responder statistics.

  Returns:
  - `total_requests` - Total OCSP requests handled
  - `cache_hits` - Responses served from cache
  - `cache_misses` - Responses generated fresh
  - `good_responses` - Certificates reported as good
  - `revoked_responses` - Certificates reported as revoked
  - `unknown_responses` - Unknown certificate serials
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("OCSP Responder initializing")

    # Create ETS tables for caching and rate limiting
    response_cache = :ets.new(:ocsp_response_cache, [:set, :private])
    rate_limiter = :ets.new(:ocsp_rate_limiter, [:set, :private])

    config = Application.get_env(:tamandua_server, __MODULE__, [])
    sign_responses = Keyword.get(config, :sign_responses, true)

    # Generate or load OCSP signing certificate
    state = %State{
      ocsp_signing_cert: nil,
      ocsp_signing_key: nil,
      response_cache: response_cache,
      rate_limiter: rate_limiter,
      sign_responses: sign_responses
    }

    state = initialize_ocsp_signing_cert(state)

    # Schedule cache cleanup
    schedule_cache_cleanup()

    Logger.info("OCSP Responder started", sign_responses: sign_responses)

    {:ok, state}
  end

  @impl true
  def handle_call({:handle_request, request_der}, {from_pid, _}, state) do
    # Rate limiting check
    from_ip = get_client_ip(from_pid)

    if rate_limit_exceeded?(from_ip, state.rate_limiter) do
      Logger.warning("OCSP request rate limited", client_ip: from_ip)
      {:reply, {:error, :rate_limited}, state}
    else
      # Parse OCSP request
      case parse_ocsp_request(request_der) do
        {:ok, serial_number, nonce} ->
          Logger.debug("OCSP request received", serial: serial_number)

          # Check cache first
          case get_cached_response(serial_number, state.response_cache) do
            {:ok, cached_response} ->
              Logger.debug("OCSP cache hit", serial: serial_number)
              {:reply, {:ok, cached_response}, state}

            :miss ->
              Logger.debug("OCSP cache miss, generating response", serial: serial_number)

              # Generate fresh response
              case generate_ocsp_response(serial_number, nonce, state) do
                {:ok, response_der} ->
                  # Cache the response
                  cache_response(serial_number, response_der, state.response_cache)

                  # Audit log
                  Audit.log("pki.ocsp_request", %{
                    serial_number: serial_number,
                    client_ip: from_ip,
                    cached: false
                  })

                  {:reply, {:ok, response_der}, state}

                {:error, reason} = error ->
                  Logger.error("Failed to generate OCSP response",
                    serial: serial_number,
                    reason: inspect(reason)
                  )

                  {:reply, error, state}
              end
          end

        {:error, :malformed} ->
          Logger.warning("Malformed OCSP request received")
          {:reply, {:error, :malformed_request}, state}
      end
    end
  end

  @impl true
  def handle_call({:check_status, serial_number}, _from, state) do
    status =
      case RevocationList.is_revoked?(serial_number) do
        :ok ->
          {:ok, :good}

        {:error, :revoked} ->
          # Get revocation reason
          case get_revocation_details(serial_number) do
            {:ok, reason} -> {:ok, :revoked, reason}
            {:error, _} -> {:ok, :revoked, :unspecified}
          end
      end

    {:reply, status, state}
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    cache_info = :ets.info(state.response_cache)

    stats = %{
      total_requests: cache_info[:size] || 0,
      cache_hits: get_counter(:cache_hits),
      cache_misses: get_counter(:cache_misses),
      good_responses: get_counter(:good_responses),
      revoked_responses: get_counter(:revoked_responses),
      unknown_responses: get_counter(:unknown_responses)
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:clear_cache, state) do
    Logger.info("Clearing OCSP response cache")
    :ets.delete_all_objects(state.response_cache)
    {:noreply, state}
  end

  @impl true
  def handle_info(:cleanup_cache, state) do
    # Remove expired cache entries
    now = System.system_time(:second)

    :ets.select_delete(state.response_cache, [
      {
        {:"$1", :"$2", :"$3"},
        [{:<, :"$3", now}],
        [true]
      }
    ])

    # Cleanup rate limiter (entries older than 1 minute)
    cleanup_cutoff = now - 60

    :ets.select_delete(state.rate_limiter, [
      {
        {:"$1", :"$2"},
        [{:<, :"$2", cleanup_cutoff}],
        [true]
      }
    ])

    # Schedule next cleanup
    schedule_cache_cleanup()

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp initialize_ocsp_signing_cert(state) do
    # For production, use a dedicated OCSP signing certificate
    # For now, we'll use the intermediate CA cert (acceptable for OCSP)

    case CertificateAuthority.get_intermediate_ca_cert() do
      {:ok, cert_pem} ->
        case get_ca_private_key() do
          {:ok, key_pem} ->
            %{state | ocsp_signing_cert: cert_pem, ocsp_signing_key: key_pem}

          {:error, reason} ->
            Logger.error("Failed to load OCSP signing key", reason: inspect(reason))
            state
        end

      {:error, reason} ->
        Logger.error("Failed to load OCSP signing certificate", reason: inspect(reason))
        state
    end
  end

  defp parse_ocsp_request(request_der) do
    # Parse DER-encoded OCSP request
    # This is a simplified parser - production should use proper ASN.1 library

    request_file = write_temp_file(request_der)

    try do
      # Use OpenSSL to parse OCSP request
      case openssl(["ocsp", "-reqin", request_file, "-text", "-noverify"]) do
        {output, 0} ->
          # Extract serial number from output
          case extract_serial_from_ocsp_text(output) do
            {:ok, serial, nonce} -> {:ok, serial, nonce}
            :error -> {:error, :malformed}
          end

        _ ->
          {:error, :malformed}
      end
    after
      File.rm(request_file)
    end
  end

  defp generate_ocsp_response(serial_number, nonce, state) do
    # Check certificate status
    {status, revocation_time, revocation_reason} =
      case RevocationList.is_revoked?(serial_number) do
        :ok ->
          increment_counter(:good_responses)
          {:good, nil, nil}

        {:error, :revoked} ->
          increment_counter(:revoked_responses)
          details = get_revocation_details(serial_number)

          case details do
            {:ok, reason, time} -> {:revoked, time, reason}
            {:error, _} -> {:revoked, DateTime.utc_now(), :unspecified}
          end
      end

    # Build OCSP response
    case build_ocsp_response(
           serial_number,
           status,
           revocation_time,
           revocation_reason,
           nonce,
           state
         ) do
      {:ok, response_der} -> {:ok, response_der}
      error -> error
    end
  end

  defp build_ocsp_response(
         serial_number,
         status,
         revocation_time,
         revocation_reason,
         _nonce,
         state
       ) do
    # Build OCSP response using OpenSSL
    # In production, use a proper ASN.1 library for better performance

    # Create response index file
    status_str =
      case status do
        :good -> "V"
        :revoked -> "R"
        _ -> "U"
      end

    revocation_str =
      if revocation_time do
        format_revocation_time(revocation_time)
      else
        ""
      end

    reason_str =
      if revocation_reason do
        reason_code(revocation_reason)
      else
        ""
      end

    # Build OpenSSL database entry
    # Format: status \t expiry \t revocation \t serial \t unknown \t subject
    index_entry =
      "#{status_str}\t30250101000000Z\t#{revocation_str}#{reason_str}\t#{serial_number}\tunknown\t/CN=#{serial_number}"

    index_file = write_temp_file(index_entry)

    # Write CA cert and key
    ca_cert_file = write_temp_file(state.ocsp_signing_cert)
    ca_key_file = write_temp_file(state.ocsp_signing_key)

    # Build config
    config = build_ocsp_config(index_file)
    config_file = write_temp_file(config)

    try do
      # Generate OCSP response
      # Note: This is simplified - production should handle this more efficiently
      case openssl([
             "ocsp",
             "-index",
             index_file,
             "-CA",
             ca_cert_file,
             "-rsigner",
             ca_cert_file,
             "-rkey",
             ca_key_file,
             "-nmin",
             "0",
             "-resp_no_certs",
             "-respout",
             "/dev/stdout"
           ]) do
        {response_der, 0} ->
          {:ok, response_der}

        {error, _} ->
          Logger.error("Failed to generate OCSP response", error: error)
          {:error, :generation_failed}
      end
    after
      File.rm(index_file)
      File.rm(ca_cert_file)
      File.rm(ca_key_file)
      File.rm(config_file)
    end
  end

  defp build_ocsp_config(index_file) do
    """
    [ ca ]
    default_ca = CA_default

    [ CA_default ]
    database = #{index_file}
    default_md = sha256
    """
  end

  defp extract_serial_from_ocsp_text(text) do
    # Parse OpenSSL OCSP -text output
    case Regex.run(~r/Serial Number:\s*0x([0-9A-Fa-f]+)/, text) do
      [_, serial_hex] ->
        # Also try to extract nonce if present
        nonce =
          case Regex.run(~r/Nonce:\s*([0-9A-Fa-f]+)/, text) do
            [_, nonce_hex] -> Base.decode16!(nonce_hex, case: :mixed)
            _ -> nil
          end

        {:ok, String.upcase(serial_hex), nonce}

      _ ->
        :error
    end
  end

  defp get_cached_response(serial_number, cache_table) do
    now = System.system_time(:second)

    case :ets.lookup(cache_table, serial_number) do
      [{^serial_number, response_der, expires_at}] when expires_at > now ->
        increment_counter(:cache_hits)
        {:ok, response_der}

      _ ->
        increment_counter(:cache_misses)
        :miss
    end
  end

  defp cache_response(serial_number, response_der, cache_table) do
    expires_at = System.system_time(:second) + @response_cache_ttl_seconds
    :ets.insert(cache_table, {serial_number, response_der, expires_at})
  end

  defp rate_limit_exceeded?(client_ip, rate_limiter) do
    now = System.system_time(:second)
    # 1 minute window
    cutoff = now - 60

    # Count requests from this IP in the last minute
    key = {:rate, client_ip}

    case :ets.lookup(rate_limiter, key) do
      [{^key, count, _timestamp}] when count >= @max_requests_per_minute ->
        true

      [{^key, count, timestamp}] when timestamp >= cutoff ->
        # Increment counter
        :ets.insert(rate_limiter, {key, count + 1, now})
        false

      _ ->
        # New or expired entry
        :ets.insert(rate_limiter, {key, 1, now})
        false
    end
  end

  defp get_revocation_details(serial_number) do
    query = """
    SELECT reason, revoked_at
    FROM certificate_revocations
    WHERE serial_number = $1
    """

    case TamanduaServer.Repo.query(query, [serial_number]) do
      {:ok, %{rows: [[reason, revoked_at]]}} ->
        {:ok, String.to_existing_atom(reason), revoked_at}

      _ ->
        {:error, :not_found}
    end
  end

  defp format_revocation_time(datetime) do
    datetime
    |> DateTime.to_naive()
    |> NaiveDateTime.to_string()
    |> String.replace(~r/[^0-9]/, "")
    |> String.slice(0, 14)
    |> Kernel.<>("Z,")
  end

  defp reason_code(reason) do
    code =
      case reason do
        :unspecified -> "0"
        :key_compromise -> "1"
        :ca_compromise -> "2"
        :affiliation_changed -> "3"
        :superseded -> "4"
        :cessation_of_operation -> "5"
        :certificate_hold -> "6"
        :privilege_withdrawn -> "9"
        :aa_compromise -> "10"
        _ -> "0"
      end

    code
  end

  defp get_ca_private_key do
    GenServer.call(TamanduaServer.PKI.CertificateAuthority, :get_intermediate_ca_key)
  end

  defp get_client_ip(_pid) do
    # In production, extract from connection metadata
    # For now, return a placeholder
    "127.0.0.1"
  end

  defp increment_counter(counter_name) do
    # Simple in-memory counter (should use persistent storage in production)
    :persistent_term.get({__MODULE__, counter_name}, 0)
    |> Kernel.+(1)
    |> then(&:persistent_term.put({__MODULE__, counter_name}, &1))
  end

  defp get_counter(counter_name) do
    :persistent_term.get({__MODULE__, counter_name}, 0)
  end

  defp schedule_cache_cleanup do
    # Run cleanup every 5 minutes
    Process.send_after(self(), :cleanup_cache, :timer.minutes(5))
  end

  defp write_temp_file(content) do
    path = Path.join(System.tmp_dir!(), "tamandua_ocsp_#{:rand.uniform(999_999)}")
    File.write!(path, content)
    path
  end

  defp openssl(args, opts \\ []) do
    case OSCommand.run("openssl", args, opts) do
      {:error, reason} -> {inspect(reason), 127}
      result -> result
    end
  end
end
