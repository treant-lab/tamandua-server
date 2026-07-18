defmodule TamanduaServer.PKI.OCSP do
  @moduledoc """
  Client-side OCSP (Online Certificate Status Protocol) revocation checker.

  Where `TamanduaServer.PKI.OCSPResponder` *answers* OCSP queries for our own
  CA, this module *asks* an OCSP responder whether a presented agent client
  certificate has been revoked. It is invoked during mTLS validation so the
  backend rejects revoked certificates instead of trusting any non-expired one.

  ## Flow

  1. Determine the responder URL from the certificate's Authority Information
     Access (AIA) extension (OID 1.3.6.1.5.5.7.48.1), falling back to a
     configured responder URL.
  2. Build a DER-encoded OCSP request (`CertID` derived from the issuer name
     hash, issuer key hash, and the subject serial number) via `:public_key`.
  3. POST the request to the responder with `Content-Type:
     application/ocsp-request` using the shared `TamanduaServer.Finch` pool.
  4. Parse the `OCSPResponse`, returning `:good`, `:revoked`, or `:unknown`.

  Successful lookups are cached for a short TTL (keyed by issuer + serial) so
  the same certificate is not re-checked on every reconnect.

  ## Configuration

      config :tamandua_server, TamanduaServer.PKI.OCSP,
        responder_url: "http://ocsp.tamandua.local",   # AIA fallback
        cache_ttl_seconds: 300,                          # status cache TTL
        request_timeout_ms: 5_000,
        soft_fail: true                                  # tolerate outages

  `soft_fail` (default `true`) means responder errors/timeouts resolve to
  `{:ok, :unknown}` and are logged as warnings rather than denying the agent,
  so a responder outage does not lock out the whole fleet. Set it to `false`
  for fail-closed behaviour.
  """

  use GenServer
  require Logger

  @cache_table :ocsp_status_cache

  # OID 1.3.6.1.5.5.7.48.1 (id-ad-ocsp) under Authority Information Access.
  @id_ad_ocsp {1, 3, 6, 1, 5, 5, 7, 48, 1}
  # OID 1.3.6.1.5.5.7.1.1 (id-pe-authorityInfoAccess).
  @id_pe_aia {1, 3, 6, 1, 5, 5, 7, 1, 1}
  # OID 1.3.14.3.2.26 (id-sha1) used for CertID name/key hashes.
  @id_sha1 {1, 3, 14, 3, 2, 26}

  @default_cache_ttl_seconds 300
  @default_request_timeout_ms 5_000

  @type status :: :good | :revoked | :unknown
  @type cert :: binary() | tuple()

  # ===========================================================================
  # Client API
  # ===========================================================================

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check the revocation status of `cert` against an OCSP responder.

  `cert` and `issuer_cert` may be raw DER binaries or the OTP/plain certificate
  tuples produced by `:public_key.pkix_decode_cert/2`.

  ## Options

    * `:responder_url` - override the AIA / configured responder URL
    * `:cache_ttl_seconds` - override the cache TTL for this lookup
    * `:soft_fail` - override the configured soft-fail behaviour
    * `:bypass_cache` - when `true`, ignore any cached status

  ## Returns

    * `{:ok, :good}` - responder reports the certificate is valid
    * `{:ok, :revoked}` - responder reports the certificate is revoked
    * `{:ok, :unknown}` - status could not be determined (also returned for
      responder errors when `soft_fail` is enabled)
    * `{:error, reason}` - a hard failure when `soft_fail` is disabled
  """
  @spec check(cert(), cert(), keyword()) :: {:ok, status()} | {:error, term()}
  def check(cert, issuer_cert, opts \\ []) do
    cert_der = to_der(cert)
    issuer_der = to_der(issuer_cert)

    with {:ok, cert_der} <- cert_der,
         {:ok, issuer_der} <- issuer_der,
         {:ok, cert_id} <- build_cert_id(cert_der, issuer_der) do
      cache_key = cache_key(cert_id)

      if Keyword.get(opts, :bypass_cache, false) do
        do_check(cert_der, issuer_der, cert_id, cache_key, opts)
      else
        case cache_lookup(cache_key) do
          {:ok, status} ->
            Logger.debug("OCSP cache hit: #{inspect(status)}")
            {:ok, status}

          :miss ->
            do_check(cert_der, issuer_der, cert_id, cache_key, opts)
        end
      end
    else
      {:error, reason} -> soft_fail_or_error(reason, opts)
    end
  end

  @doc """
  Clear the OCSP status cache. Primarily useful for tests and tooling.
  """
  @spec clear_cache() :: :ok
  def clear_cache do
    if :ets.whereis(@cache_table) != :undefined do
      :ets.delete_all_objects(@cache_table)
    end

    :ok
  end

  # ===========================================================================
  # Server callbacks
  # ===========================================================================

  @impl true
  def init(_opts) do
    # Public, read-concurrent ETS table so callers read the cache without
    # routing every lookup through the GenServer (mirrors OCSPResponder's
    # ETS-backed caching). The GenServer simply owns the table's lifetime.
    table =
      :ets.new(@cache_table, [
        :set,
        :named_table,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    Logger.info("PKI.OCSP revocation checker started (cache=#{inspect(table)})")
    {:ok, %{table: table}}
  end

  # ===========================================================================
  # Internal: orchestration
  # ===========================================================================

  defp do_check(cert_der, _issuer_der, cert_id, cache_key, opts) do
    with {:ok, url} <- responder_url(cert_der, opts),
         {:ok, request_der} <- build_request(cert_id),
         {:ok, response_der} <- post_request(url, request_der, opts),
         {:ok, status} <- parse_response(response_der) do
      cache_put(cache_key, status, opts)
      {:ok, status}
    else
      {:error, reason} -> soft_fail_or_error(reason, opts)
    end
  end

  defp soft_fail_or_error(reason, opts) do
    if soft_fail?(opts) do
      Logger.warning("OCSP check soft-failing as :unknown: #{inspect(reason)}")
      {:ok, :unknown}
    else
      Logger.warning("OCSP check failed (fail-closed): #{inspect(reason)}")
      {:error, reason}
    end
  end

  # ===========================================================================
  # Internal: certificate / request encoding via :public_key
  # ===========================================================================

  defp to_der(der) when is_binary(der), do: {:ok, der}
  defp to_der({:Certificate, der, _}) when is_binary(der), do: {:ok, der}

  defp to_der({:OTPCertificate, _, _, _} = otp) do
    {:ok, :public_key.pkix_encode(:OTPCertificate, otp, :otp)}
  rescue
    e -> {:error, {:cert_encode_failed, e}}
  end

  defp to_der(_), do: {:error, :unsupported_certificate}

  # Build the OCSP CertID for the subject certificate. Per RFC 6960 the CertID
  # binds the issuer (name hash + public-key hash) with the subject serial, so
  # we decode the subject for its serial and the issuer for its name/key.
  defp build_cert_id(cert_der, issuer_der) do
    {:OTPCertificate, tbs_subject, _, _} = :public_key.pkix_decode_cert(cert_der, :otp)
    {:OTPTBSCertificate, _ver, serial, _sig, _iss, _val, _subj, _pki, _, _, _} = tbs_subject

    {:OTPCertificate, tbs_issuer, _, _} = :public_key.pkix_decode_cert(issuer_der, :otp)
    {:OTPTBSCertificate, _v2, _s2, _sa2, issuer_name, _val2, _subj2, issuer_pki, _, _, _} =
      tbs_issuer

    issuer_name_der = :public_key.pkix_encode(:Name, issuer_name, :otp)
    issuer_name_hash = :crypto.hash(:sha, issuer_name_der)
    issuer_key_hash = :crypto.hash(:sha, issuer_public_key_bitstring(issuer_pki))

    cert_id =
      {:CertID, {:AlgorithmIdentifier, @id_sha1, <<5, 0>>}, issuer_name_hash, issuer_key_hash,
       serial}

    {:ok, cert_id}
  rescue
    e -> {:error, {:cert_id_failed, e}}
  end

  # The CertID issuerKeyHash is the SHA-1 of the issuer's subjectPublicKey BIT
  # STRING contents (not the full SubjectPublicKeyInfo).
  defp issuer_public_key_bitstring({:OTPSubjectPublicKeyInfo, _algo, pub_key} = pki) do
    der = :public_key.pkix_encode(:OTPSubjectPublicKeyInfo, pki, :otp)
    # Extract the trailing BIT STRING (subjectPublicKey) from the SPKI DER.
    case der do
      _ when is_binary(der) -> spki_public_key_bits(der, pub_key)
    end
  end

  # Fall back to encoding just the key when SPKI parsing is unavailable.
  defp spki_public_key_bits(_spki_der, {:ECPoint, point}) when is_binary(point), do: point

  defp spki_public_key_bits(_spki_der, key) do
    :public_key.der_encode(:RSAPublicKey, key)
  rescue
    _ -> :erlang.term_to_binary(key)
  end

  # Build the DER-encoded OCSPRequest (single Request, no signature, no nonce).
  defp build_request(cert_id) do
    request = {:Request, cert_id, :asn1_NOVALUE}
    tbs = {:TBSRequest, :asn1_NOVALUE, :asn1_NOVALUE, [request], :asn1_NOVALUE}
    ocsp_request = {:OCSPRequest, tbs, :asn1_NOVALUE}

    {:ok, :public_key.der_encode(:OCSPRequest, ocsp_request)}
  rescue
    e -> {:error, {:request_encode_failed, e}}
  end

  # ===========================================================================
  # Internal: HTTP round-trip
  # ===========================================================================

  defp post_request(url, request_der, opts) do
    timeout = Keyword.get(opts, :request_timeout_ms, config(:request_timeout_ms, @default_request_timeout_ms))

    headers = [
      {"content-type", "application/ocsp-request"},
      {"accept", "application/ocsp-response"}
    ]

    request = Finch.build(:post, url, headers, request_der)

    case Finch.request(request, TamanduaServer.Finch, receive_timeout: timeout) do
      {:ok, %{status: 200, body: body}} when is_binary(body) and byte_size(body) > 0 ->
        {:ok, body}

      {:ok, %{status: status}} ->
        {:error, {:responder_http_status, status}}

      {:error, reason} ->
        {:error, {:responder_unreachable, reason}}
    end
  rescue
    e -> {:error, {:responder_request_failed, e}}
  end

  # ===========================================================================
  # Internal: response parsing
  # ===========================================================================

  defp parse_response(response_der) do
    case :public_key.der_decode(:OCSPResponse, response_der) do
      {:OCSPResponse, :successful, {:ResponseBytes, _type, basic_der}} ->
        parse_basic_response(basic_der)

      {:OCSPResponse, :successful, response_bytes} ->
        parse_response_bytes(response_bytes)

      {:OCSPResponse, other_status, _} ->
        {:error, {:responder_status, other_status}}

      other ->
        {:error, {:unexpected_response, other}}
    end
  rescue
    e -> {:error, {:response_decode_failed, e}}
  end

  defp parse_response_bytes({:ResponseBytes, _type, basic_der}), do: parse_basic_response(basic_der)
  defp parse_response_bytes(_), do: {:error, :missing_response_bytes}

  defp parse_basic_response(basic_der) do
    case :public_key.der_decode(:BasicOCSPResponse, basic_der) do
      {:BasicOCSPResponse, tbs, _sig_algo, _sig, _certs} ->
        extract_single_status(tbs)

      other ->
        {:error, {:unexpected_basic_response, other}}
    end
  rescue
    e -> {:error, {:basic_response_decode_failed, e}}
  end

  defp extract_single_status({:ResponseData, _ver, _rid, _produced_at, responses, _exts}) do
    case responses do
      [{:SingleResponse, _cert_id, cert_status, _this, _next, _exts} | _] ->
        {:ok, normalize_status(cert_status)}

      _ ->
        {:error, :no_single_response}
    end
  end

  defp extract_single_status(_), do: {:error, :unexpected_response_data}

  # CertStatus is a CHOICE: good (NULL), revoked (RevokedInfo), unknown (NULL).
  defp normalize_status({:good, _}), do: :good
  defp normalize_status(:good), do: :good
  defp normalize_status({:revoked, _}), do: :revoked
  defp normalize_status({:unknown, _}), do: :unknown
  defp normalize_status(:unknown), do: :unknown
  defp normalize_status(_), do: :unknown

  # ===========================================================================
  # Internal: responder URL discovery (AIA -> config fallback)
  # ===========================================================================

  defp responder_url(cert_der, opts) do
    cond do
      url = Keyword.get(opts, :responder_url) ->
        {:ok, url}

      url = aia_ocsp_url(cert_der) ->
        {:ok, url}

      url = config(:responder_url, nil) ->
        {:ok, url}

      true ->
        {:error, :no_responder_url}
    end
  end

  defp aia_ocsp_url(cert_der) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(cert_der, :otp)
    {:OTPTBSCertificate, _v, _s, _sa, _iss, _val, _subj, _pki, _, _, exts} = tbs

    exts
    |> List.wrap()
    |> Enum.find_value(fn
      {:Extension, @id_pe_aia, _crit, aia} -> aia_to_url(aia)
      _ -> nil
    end)
  rescue
    _ -> nil
  end

  defp aia_to_url(aia) when is_list(aia) do
    Enum.find_value(aia, fn
      {:AccessDescription, @id_ad_ocsp, {:uniformResourceIdentifier, uri}} -> to_string(uri)
      _ -> nil
    end)
  end

  defp aia_to_url(_), do: nil

  # ===========================================================================
  # Internal: cache (ETS, short TTL)
  # ===========================================================================

  defp cache_key({:CertID, _alg, name_hash, key_hash, serial}) do
    :crypto.hash(:sha256, [name_hash, key_hash, :erlang.term_to_binary(serial)])
  end

  defp cache_lookup(key) do
    now = System.system_time(:second)

    case safe_ets_lookup(key) do
      [{^key, status, expires_at}] when expires_at > now -> {:ok, status}
      _ -> :miss
    end
  end

  defp cache_put(key, status, opts) do
    # Only cache definitive answers; :unknown should be re-checked promptly.
    if status in [:good, :revoked] do
      ttl = Keyword.get(opts, :cache_ttl_seconds, config(:cache_ttl_seconds, @default_cache_ttl_seconds))
      expires_at = System.system_time(:second) + ttl
      safe_ets_insert({key, status, expires_at})
    end

    :ok
  end

  defp safe_ets_lookup(key) do
    if :ets.whereis(@cache_table) != :undefined, do: :ets.lookup(@cache_table, key), else: []
  rescue
    _ -> []
  end

  defp safe_ets_insert(tuple) do
    if :ets.whereis(@cache_table) != :undefined, do: :ets.insert(@cache_table, tuple)
  rescue
    _ -> false
  end

  # ===========================================================================
  # Internal: config helpers
  # ===========================================================================

  defp soft_fail?(opts) do
    Keyword.get(opts, :soft_fail, config(:soft_fail, true))
  end

  defp config(key, default) do
    :tamandua_server
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key, default)
  end
end
