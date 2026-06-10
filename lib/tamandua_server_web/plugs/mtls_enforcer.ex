defmodule TamanduaServerWeb.Plugs.MtlsEnforcer do
  @moduledoc """
  Plug for enforcing mutual TLS (mTLS) on protected endpoints.

  In production, validates client certificates against a CA chain.
  In dev/test, can bypass validation unless explicitly required.

  ## Configuration

  Set in runtime.exs:
      config :tamandua_server,
        require_mtls: true,
        ca_cert_path: "/etc/tamandua/ca.crt",
        mtls_paths: ["/socket/agent", "/api/v1/agents/telemetry"]

  ## Usage

  In your router:
      plug TamanduaServerWeb.Plugs.MtlsEnforcer,
        required: true,
        paths: ["/socket/agent"]
  """

  import Plug.Conn
  require Logger
  alias TamanduaServer.OSCommand

  @behaviour Plug

  @default_paths ["/socket/agent", "/api/v1/agents/telemetry"]

  @impl Plug
  def init(opts) do
    [
      required: Keyword.get(opts, :required, false),
      paths: Keyword.get(opts, :paths, @default_paths)
    ]
  end

  @impl Plug
  def call(conn, opts) do
    required = opts[:required]
    protected_paths = opts[:paths]

    if path_protected?(conn.request_path, protected_paths) do
      if required do
        enforce_mtls(conn)
      else
        bypass_mtls(conn)
      end
    else
      conn
    end
  end

  defp path_protected?(request_path, protected_paths) do
    Enum.any?(protected_paths, fn path ->
      String.starts_with?(request_path, path)
    end)
  end

  defp enforce_mtls(conn) do
    case extract_client_cert(conn) do
      {:ok, cert_der} ->
        validate_and_assign(conn, cert_der)

      {:error, :missing_certificate} ->
        reject_connection(conn, "Client certificate required")
    end
  end

  defp extract_client_cert(conn) do
    case get_in(conn.private, [:peer_data, :ssl_cert]) do
      nil ->
        {:error, :missing_certificate}

      cert_der when is_binary(cert_der) ->
        {:ok, cert_der}

      _ ->
        {:error, :missing_certificate}
    end
  end

  defp validate_and_assign(conn, cert_der) do
    case validate_certificate(cert_der) do
      {:ok, cert_info} ->
        assign(conn, :client_cert, cert_info)

      {:error, reason} ->
        reject_connection(conn, "Certificate validation failed: #{reason}")
    end
  end

  defp reject_connection(conn, message) do
    Logger.warning("mTLS enforcement rejected connection: #{message}")

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(403, Jason.encode!(%{error: message}))
    |> halt()
  end

  defp bypass_mtls(conn) do
    Logger.debug("mTLS validation bypassed (dev/test mode)")
    assign(conn, :mtls_bypassed, true)
  end

  @doc """
  Validates a client certificate against the configured CA.

  Returns {:ok, cert_info} if valid, {:error, reason} otherwise.
  """
  def validate_certificate(cert_der) do
    ca_cert_path = Application.get_env(:tamandua_server, :ca_cert_path)

    case load_ca_bundle(ca_cert_path) do
      {:ok, ca_pem} ->
        validate_against_ca(cert_der, ca_pem)

      {:error, reason} ->
        {:error, "CA bundle unavailable: #{inspect(reason)}"}
    end
  end

  defp load_ca_bundle(path) when is_binary(path) and path != "" do
    case File.read(path) do
      {:ok, ca_pem} -> {:ok, ca_pem}
      {:error, _reason} -> load_ca_bundle_from_pki()
    end
  end

  defp load_ca_bundle(_), do: load_ca_bundle_from_pki()

  defp load_ca_bundle_from_pki do
    with :ok <- TamanduaServer.PKI.CertificateAuthority.ensure_initialized(),
         {:ok, export} <- TamanduaServer.PKI.CertificateAuthority.export_for_agents() do
      {:ok, export.ca_bundle_pem}
    end
  rescue
    e -> {:error, e}
  catch
    :exit, reason -> {:error, reason}
  end

  defp validate_against_ca(cert_der, ca_pem) do
    case :public_key.pkix_decode_cert(cert_der, :otp) do
      {:OTPCertificate, _tbs, _sig_algo, _signature} = cert ->
        case extract_cn(cert) do
          {:ok, cn} ->
            if verify_against_ca_bundle(cert_der, ca_pem) do
              {:ok, %{cn: cn, validated: true}}
            else
              {:error, :invalid_certificate_chain}
            end

          :error ->
            {:error, :invalid_subject}
        end

      _ ->
        {:error, :invalid_certificate}
    end
  rescue
    e ->
      Logger.error("Certificate validation error: #{Exception.message(e)}")
      {:error, :validation_exception}
  end

  defp verify_against_ca_bundle(cert_der, ca_pem) do
    cert_file =
      write_temp_file(:public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}]))

    ca_file = write_temp_file(ca_pem)

    try do
      case OSCommand.run("openssl", ["verify", "-CAfile", ca_file, cert_file]) do
        {output, 0} ->
          String.contains?(output, "OK")

        {:error, reason} ->
          Logger.warning("mTLS certificate chain verification could not run: #{inspect(reason)}")
          false

        {error, _} ->
          Logger.warning("mTLS certificate chain verification failed: #{String.trim(error)}")
          false
      end
    after
      File.rm(cert_file)
      File.rm(ca_file)
    end
  end

  defp write_temp_file(content) do
    path =
      Path.join(System.tmp_dir!(), "tamandua_mtls_plug_#{System.unique_integer([:positive])}.pem")

    File.write!(path, content)
    path
  end

  @doc """
  Extracts the Common Name (CN) from a certificate.

  Returns {:ok, cn} or :error.
  """
  def extract_cn(cert) when is_tuple(cert) do
    try do
      # Navigate OTP certificate structure
      # cert is {:OTPCertificate, tbsCertificate, signatureAlgorithm, signature}
      tbs_cert = elem(cert, 1)
      subject = elem(tbs_cert, 6)

      # Subject is a list of RDNSequence
      # Search for CN (Common Name) attribute
      cn =
        subject
        |> Enum.find_value(fn rdn_sequence ->
          Enum.find_value(rdn_sequence, fn attr ->
            # attr is {:AttributeTypeAndValue, type, value}
            case attr do
              {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, cn_value}} ->
                List.to_string(cn_value)

              {:AttributeTypeAndValue, {2, 5, 4, 3}, cn_value} when is_binary(cn_value) ->
                cn_value

              _ ->
                nil
            end
          end)
        end)

      if cn, do: {:ok, cn}, else: :error
    rescue
      _ -> :error
    end
  end

  def extract_cn(_), do: :error
end
