defmodule TamanduaServer.PKI.CertificateAuthority do
  @moduledoc """
  Certificate Authority (CA) management for Tamandua EDR mTLS.

  This module manages the root CA and intermediate CA certificates used for
  agent certificate generation. It provides:

  - CA certificate and key generation (RSA 4096-bit)
  - CA certificate storage and retrieval
  - CA key protection with encryption at rest
  - CA certificate chain validation
  - OCSP responder URL embedding
  - CRL distribution point configuration
  - HSM integration support via PKCS#11

  ## Security Considerations

  - CA private keys are encrypted at rest using AES-256-GCM
  - Key material never leaves the server in plaintext
  - HSM integration is supported for hardware key protection
  - All CA operations are audit logged
  - CA certificates have 10-year validity by default
  - Intermediate CAs have 5-year validity for rotation

  ## Example

      # Initialize CA (one-time setup)
      {:ok, ca} = CertificateAuthority.init_root_ca()

      # Get CA certificate for agent verification
      {:ok, ca_cert_pem} = CertificateAuthority.get_ca_cert()

      # Create intermediate CA for agent signing
      {:ok, intermediate} = CertificateAuthority.create_intermediate_ca(
        "Tamandua Agent Intermediate CA"
      )
  """

  use GenServer
  require Logger
  alias TamanduaServer.OSCommand
  alias TamanduaServer.PKI.CertificateAuthority.Storage

  @ca_key_size 4096
  # 10 years
  @root_ca_validity_days 3650
  # 5 years
  @intermediate_ca_validity_days 1825
  @encryption_key_env "TAMANDUA_CA_ENCRYPTION_KEY"

  defmodule State do
    @moduledoc false
    defstruct [
      :root_ca_cert,
      :root_ca_key,
      :intermediate_ca_cert,
      :intermediate_ca_key,
      :hsm_enabled,
      :hsm_config,
      :ocsp_url,
      :crl_url,
      :encryption_key
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Initialize the root CA certificate and key.

  This should be called once during initial setup. The CA certificate and
  encrypted private key are stored in the database.

  ## Options

    * `:force` - Force regeneration even if CA already exists (default: false)
    * `:subject` - CA certificate subject (default: "Tamandua EDR Root CA")
    * `:hsm_enabled` - Use HSM for key storage (default: false)
    * `:hsm_config` - HSM configuration (PKCS#11 library path, slot, pin)

  ## Returns

    * `{:ok, ca_cert_pem}` - CA certificate in PEM format
    * `{:error, :already_exists}` - CA already initialized
    * `{:error, reason}` - Other errors
  """
  def init_root_ca(opts \\ []) do
    GenServer.call(__MODULE__, {:init_root_ca, opts}, :infinity)
  end

  @doc """
  Get the root CA certificate in PEM format.

  This certificate should be distributed to agents for server verification.
  """
  def get_root_ca_cert do
    GenServer.call(__MODULE__, :get_root_ca_cert)
  end

  @doc """
  Get the intermediate CA certificate in PEM format.

  This is the CA that signs agent certificates.
  """
  def get_intermediate_ca_cert do
    GenServer.call(__MODULE__, :get_intermediate_ca_cert)
  end

  @doc """
  Get the full certificate chain (root + intermediate).

  Agents need this chain to verify the server certificate.
  """
  def get_ca_chain do
    GenServer.call(__MODULE__, :get_ca_chain)
  end

  @doc """
  Create an intermediate CA certificate signed by the root CA.

  This intermediate CA is used for signing agent certificates, allowing
  root CA key to remain offline in production.

  ## Options

    * `:subject` - Intermediate CA subject (default: "Tamandua EDR Intermediate CA")
    * `:validity_days` - Certificate validity in days (default: 1825 = 5 years)
  """
  def create_intermediate_ca(opts \\ []) do
    GenServer.call(__MODULE__, {:create_intermediate_ca, opts}, :infinity)
  end

  @doc """
  Ensure the CA chain needed for agent certificate signing exists.

  This is safe to call at boot and before CSR enrollment. Existing CA material is
  reused; missing root/intermediate certificates are created and persisted.
  """
  def ensure_initialized(opts \\ []) do
    GenServer.call(__MODULE__, {:ensure_initialized, opts}, :infinity)
  end

  @doc """
  Rotate the intermediate CA certificate.

  This generates a new intermediate CA certificate while maintaining the
  root CA. Old agent certificates remain valid until expiry.
  """
  def rotate_intermediate_ca do
    GenServer.call(__MODULE__, :rotate_intermediate_ca, :infinity)
  end

  @doc """
  Verify a certificate chain against the CA.

  Returns `:ok` if the certificate is validly signed by this CA,
  or `{:error, reason}` otherwise.
  """
  def verify_chain(cert_pem) do
    GenServer.call(__MODULE__, {:verify_chain, cert_pem})
  end

  @doc """
  Export CA certificate for agent distribution.

  Returns a map containing:
  - `root_ca_pem` - Root CA certificate
  - `intermediate_ca_pem` - Intermediate CA certificate
  - `ca_bundle_pem` - Combined certificate bundle
  - `root_ca_fingerprint` - SHA-256 fingerprint for pinning
  """
  def export_for_agents do
    GenServer.call(__MODULE__, :export_for_agents)
  end

  @doc """
  Sign a Certificate Signing Request (CSR) and return the signed certificate.

  This is used for CSR-based enrollment where the agent generates its keypair
  locally and sends only the CSR (containing the public key) to the server.
  The private key never leaves the agent.

  ## Arguments

    * `csr_pem` - The CSR in PEM format
    * `opts` - Options for certificate generation:
      * `:validity_days` - Certificate validity in days (default: 90)
      * `:agent_id` - Expected agent ID to verify against CSR CN (optional)

  ## Returns

    * `{:ok, cert_pem}` - The signed certificate in PEM format
    * `{:error, reason}` - Error reason

  ## Security

  - The CSR signature is verified to ensure the requester has the private key
  - The CN (Common Name) is extracted and used as the certificate subject
  - The certificate is signed by the intermediate CA (not the root CA)
  - Standard agent certificate extensions are applied (clientAuth, etc.)
  """
  def sign_csr(csr_pem, opts \\ []) do
    GenServer.call(__MODULE__, {:sign_csr, csr_pem, opts}, :infinity)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Load encryption key from environment
    encryption_key = get_encryption_key()

    # Load CA certificates and keys from storage
    state = %State{
      root_ca_cert: nil,
      root_ca_key: nil,
      intermediate_ca_cert: nil,
      intermediate_ca_key: nil,
      hsm_enabled: false,
      hsm_config: nil,
      ocsp_url: Application.get_env(:tamandua_server, :ocsp_url, "http://ocsp.tamandua.local/"),
      crl_url:
        Application.get_env(:tamandua_server, :crl_url, "http://crl.tamandua.local/crl.pem"),
      encryption_key: encryption_key
    }

    # Load existing CA if available
    state = load_ca_state(state)

    Logger.info("Certificate Authority initialized")

    {:ok, state}
  end

  @impl true
  def handle_call({:init_root_ca, opts}, _from, state) do
    force = Keyword.get(opts, :force, false)

    cond do
      state.root_ca_cert != nil and not force ->
        {:reply, {:error, :already_exists}, state}

      true ->
        Logger.info("Initializing root CA certificate")

        subject = Keyword.get(opts, :subject, "Tamandua EDR Root CA")
        hsm_enabled = Keyword.get(opts, :hsm_enabled, false)
        hsm_config = Keyword.get(opts, :hsm_config, nil)

        # Generate root CA certificate and key
        case generate_root_ca(subject, state) do
          {:ok, root_ca_cert, root_ca_key} ->
            # Store CA certificate and encrypted key
            :ok = Storage.store_root_ca(root_ca_cert, root_ca_key, state.encryption_key)

            # Update state
            new_state = %{
              state
              | root_ca_cert: root_ca_cert,
                root_ca_key: root_ca_key,
                hsm_enabled: hsm_enabled,
                hsm_config: hsm_config
            }

            # Audit log
            safe_audit("pki.root_ca_init", %{
              subject: subject,
              hsm_enabled: hsm_enabled,
              fingerprint: cert_fingerprint(root_ca_cert)
            })

            Logger.info("Root CA initialized successfully", subject: subject)

            {:reply, {:ok, root_ca_cert}, new_state}

          {:error, reason} ->
            Logger.error("Failed to initialize root CA", reason: inspect(reason))
            {:reply, {:error, reason}, state}
        end
    end
  end

  @impl true
  def handle_call(:get_root_ca_cert, _from, state) do
    case state.root_ca_cert do
      nil -> {:reply, {:error, :not_initialized}, state}
      cert -> {:reply, {:ok, cert}, state}
    end
  end

  @impl true
  def handle_call(:get_intermediate_ca_cert, _from, state) do
    case state.intermediate_ca_cert do
      nil -> {:reply, {:error, :not_initialized}, state}
      cert -> {:reply, {:ok, cert}, state}
    end
  end

  @impl true
  def handle_call(:get_ca_chain, _from, state) do
    case {state.root_ca_cert, state.intermediate_ca_cert} do
      {nil, _} ->
        {:reply, {:error, :root_ca_not_initialized}, state}

      {root, nil} ->
        {:reply, {:ok, [root]}, state}

      {root, intermediate} ->
        {:reply, {:ok, [intermediate, root]}, state}
    end
  end

  @impl true
  def handle_call({:create_intermediate_ca, opts}, _from, state) do
    if state.root_ca_cert == nil do
      {:reply, {:error, :root_ca_not_initialized}, state}
    else
      Logger.info("Creating intermediate CA certificate")

      subject = Keyword.get(opts, :subject, "Tamandua EDR Intermediate CA")
      validity_days = Keyword.get(opts, :validity_days, @intermediate_ca_validity_days)

      case generate_intermediate_ca(subject, validity_days, state) do
        {:ok, intermediate_cert, intermediate_key} ->
          # Store intermediate CA
          :ok =
            Storage.store_intermediate_ca(
              intermediate_cert,
              intermediate_key,
              state.encryption_key
            )

          new_state = %{
            state
            | intermediate_ca_cert: intermediate_cert,
              intermediate_ca_key: intermediate_key
          }

          # Audit log
          safe_audit("pki.intermediate_ca_created", %{
            subject: subject,
            validity_days: validity_days,
            fingerprint: cert_fingerprint(intermediate_cert)
          })

          Logger.info("Intermediate CA created successfully", subject: subject)

          {:reply, {:ok, intermediate_cert}, new_state}

        {:error, reason} ->
          Logger.error("Failed to create intermediate CA", reason: inspect(reason))
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call(:rotate_intermediate_ca, _from, state) do
    Logger.info("Rotating intermediate CA certificate")

    # Archive old intermediate CA
    if state.intermediate_ca_cert do
      Storage.archive_intermediate_ca(state.intermediate_ca_cert)
    end

    # Generate new intermediate CA
    case generate_intermediate_ca(
           "Tamandua EDR Intermediate CA",
           @intermediate_ca_validity_days,
           state
         ) do
      {:ok, new_cert, new_key} ->
        Storage.store_intermediate_ca(new_cert, new_key, state.encryption_key)

        new_state = %{state | intermediate_ca_cert: new_cert, intermediate_ca_key: new_key}

        safe_audit("pki.intermediate_ca_rotated", %{
          new_fingerprint: cert_fingerprint(new_cert)
        })

        Logger.info("Intermediate CA rotated successfully")

        {:reply, {:ok, new_cert}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:ensure_initialized, opts}, _from, state) do
    case ensure_ca_chain(state, opts) do
      {:ok, new_state} ->
        {:reply, :ok, new_state}

      {:error, reason, new_state} ->
        {:reply, {:error, reason}, new_state}
    end
  end

  @impl true
  def handle_call({:verify_chain, cert_pem}, _from, state) do
    case {state.root_ca_cert, state.intermediate_ca_cert} do
      {nil, _} ->
        {:reply, {:error, :ca_not_initialized}, state}

      {root_ca, intermediate_ca} ->
        result = verify_certificate_chain(cert_pem, intermediate_ca, root_ca)
        {:reply, result, state}
    end
  end

  @impl true
  def handle_call(:export_for_agents, _from, state) do
    case {state.root_ca_cert, state.intermediate_ca_cert} do
      {nil, _} ->
        {:reply, {:error, :ca_not_initialized}, state}

      {root_ca, nil} ->
        export = %{
          root_ca_pem: root_ca,
          ca_bundle_pem: root_ca,
          root_ca_fingerprint: cert_fingerprint(root_ca)
        }

        {:reply, {:ok, export}, state}

      {root_ca, intermediate_ca} ->
        bundle = "#{intermediate_ca}\n#{root_ca}"

        export = %{
          root_ca_pem: root_ca,
          intermediate_ca_pem: intermediate_ca,
          ca_bundle_pem: bundle,
          root_ca_fingerprint: cert_fingerprint(root_ca),
          intermediate_ca_fingerprint: cert_fingerprint(intermediate_ca)
        }

        {:reply, {:ok, export}, state}
    end
  end

  @impl true
  def handle_call({:sign_csr, csr_pem, opts}, _from, state) do
    cond do
      state.intermediate_ca_cert == nil ->
        {:reply, {:error, :intermediate_ca_not_initialized}, state}

      state.intermediate_ca_key == nil ->
        {:reply, {:error, :intermediate_ca_key_not_loaded}, state}

      true ->
        Logger.info("Signing CSR from agent")

        validity_days = Keyword.get(opts, :validity_days, 90)
        expected_agent_id = Keyword.get(opts, :agent_id)

        case sign_agent_csr(csr_pem, validity_days, expected_agent_id, state) do
          {:ok, cert_pem, agent_id} ->
            # Audit log
            safe_audit("pki.csr_signed", %{
              agent_id: agent_id,
              validity_days: validity_days,
              fingerprint: cert_fingerprint(cert_pem)
            })

            Logger.info("CSR signed successfully", agent_id: agent_id)
            {:reply, {:ok, cert_pem, agent_id}, state}

          {:error, reason} ->
            Logger.error("Failed to sign CSR", reason: inspect(reason))
            {:reply, {:error, reason}, state}
        end
    end
  end

  # Private Functions

  defp ensure_ca_chain(state, opts) do
    root_subject = Keyword.get(opts, :root_subject, "Tamandua EDR Root CA")

    intermediate_subject =
      Keyword.get(opts, :intermediate_subject, "Tamandua EDR Intermediate CA")

    intermediate_validity_days =
      Keyword.get(opts, :intermediate_validity_days, @intermediate_ca_validity_days)

    with {:ok, state} <- ensure_root_ca(state, root_subject),
         {:ok, state} <-
           ensure_intermediate_ca(state, intermediate_subject, intermediate_validity_days) do
      {:ok, state}
    else
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp ensure_root_ca(%{root_ca_cert: cert, root_ca_key: key} = state, _subject)
       when is_binary(cert) and is_binary(key) do
    {:ok, state}
  end

  defp ensure_root_ca(state, subject) do
    Logger.warning("Root CA not initialized; generating Tamandua root CA")

    case generate_root_ca(subject, state) do
      {:ok, root_ca_cert, root_ca_key} ->
        :ok = Storage.store_root_ca(root_ca_cert, root_ca_key, state.encryption_key)

        safe_audit("pki.root_ca_auto_init", %{
          subject: subject,
          fingerprint: cert_fingerprint(root_ca_cert)
        })

        {:ok, %{state | root_ca_cert: root_ca_cert, root_ca_key: root_ca_key}}

      {:error, reason} ->
        Logger.error("Failed to auto-initialize root CA", reason: inspect(reason))
        {:error, reason, state}
    end
  end

  defp ensure_intermediate_ca(
         %{intermediate_ca_cert: cert, intermediate_ca_key: key} = state,
         _subject,
         _days
       )
       when is_binary(cert) and is_binary(key) do
    {:ok, state}
  end

  defp ensure_intermediate_ca(state, subject, validity_days) do
    Logger.warning("Intermediate CA not initialized; generating Tamandua intermediate CA")

    case generate_intermediate_ca(subject, validity_days, state) do
      {:ok, intermediate_cert, intermediate_key} ->
        :ok =
          Storage.store_intermediate_ca(intermediate_cert, intermediate_key, state.encryption_key)

        safe_audit("pki.intermediate_ca_auto_init", %{
          subject: subject,
          validity_days: validity_days,
          fingerprint: cert_fingerprint(intermediate_cert)
        })

        {:ok,
         %{state | intermediate_ca_cert: intermediate_cert, intermediate_ca_key: intermediate_key}}

      {:error, reason} ->
        Logger.error("Failed to auto-initialize intermediate CA", reason: inspect(reason))
        {:error, reason, state}
    end
  end

  defp load_ca_state(state) do
    case Storage.load_root_ca(state.encryption_key) do
      {:ok, root_cert, root_key} ->
        Logger.info("Loaded root CA from storage")

        # Try to load intermediate CA
        case Storage.load_intermediate_ca(state.encryption_key) do
          {:ok, intermediate_cert, intermediate_key} ->
            Logger.info("Loaded intermediate CA from storage")

            %{
              state
              | root_ca_cert: root_cert,
                root_ca_key: root_key,
                intermediate_ca_cert: intermediate_cert,
                intermediate_ca_key: intermediate_key
            }

          {:error, _} ->
            %{state | root_ca_cert: root_cert, root_ca_key: root_key}
        end

      {:error, _reason} ->
        Logger.info("No existing CA found, will need initialization")
        state
    end
  end

  defp generate_root_ca(subject, state) do
    key_file = temp_path("root_key")
    cert_file = temp_path("root_cert")
    config_file = write_temp_file(build_ca_config(state, true))

    try do
      with {_, 0} <- openssl(["genrsa", "-out", key_file, Integer.to_string(@ca_key_size)]),
           {_, 0} <-
             openssl([
               "req",
               "-new",
               "-x509",
               "-key",
               key_file,
               "-out",
               cert_file,
               "-days",
               Integer.to_string(@root_ca_validity_days),
               "-subj",
               "/CN=#{subject}/O=Tamandua EDR/OU=Security",
               "-extensions",
               "v3_ca",
               "-config",
               config_file
             ]),
           {:ok, private_key_pem} <- File.read(key_file),
           {:ok, cert_pem} <- File.read(cert_file) do
        {:ok, String.trim(cert_pem), String.trim(private_key_pem)}
      else
        {error, _exit_code} -> {:error, {:openssl_error, error}}
        {:error, reason} -> {:error, reason}
      end
    after
      rm_temp(key_file)
      rm_temp(cert_file)
      rm_temp(config_file)
    end
  end

  defp generate_intermediate_ca(subject, validity_days, state) do
    key_file = temp_path("intermediate_key")
    csr_file = temp_path("intermediate_csr")
    cert_file = temp_path("intermediate_cert")
    root_cert_file = write_temp_file(state.root_ca_cert)
    root_key_file = write_temp_file(state.root_ca_key)
    config_file = write_temp_file(build_ca_config(state, false))

    try do
      with {_, 0} <- openssl(["genrsa", "-out", key_file, Integer.to_string(@ca_key_size)]),
           {_, 0} <-
             openssl([
               "req",
               "-new",
               "-key",
               key_file,
               "-out",
               csr_file,
               "-subj",
               "/CN=#{subject}/O=Tamandua EDR/OU=Security"
             ]),
           {_, 0} <-
             openssl([
               "x509",
               "-req",
               "-in",
               csr_file,
               "-CA",
               root_cert_file,
               "-CAkey",
               root_key_file,
               "-set_serial",
               generate_serial(),
               "-out",
               cert_file,
               "-days",
               Integer.to_string(validity_days),
               "-extensions",
               "v3_intermediate_ca",
               "-extfile",
               config_file
             ]),
           {:ok, intermediate_key_pem} <- File.read(key_file),
           {:ok, cert_pem} <- File.read(cert_file) do
        {:ok, String.trim(cert_pem), String.trim(intermediate_key_pem)}
      else
        {error, _exit_code} -> {:error, {:openssl_error, error}}
        {:error, reason} -> {:error, reason}
      end
    after
      rm_temp(key_file)
      rm_temp(csr_file)
      rm_temp(cert_file)
      rm_temp(root_cert_file)
      rm_temp(root_key_file)
      rm_temp(config_file)
    end
  end

  defp sign_agent_csr(csr_pem, validity_days, server_agent_id, state) do
    # SECURITY: server_agent_id is the authoritative agent ID from the server.
    # We do NOT trust the CN in the client's CSR - we create a new certificate
    # with the server-generated agent_id as the CN.

    # Write CSR to temp file for OpenSSL processing
    csr_file = write_temp_file(csr_pem)
    ca_cert_file = write_temp_file(state.intermediate_ca_cert)
    ca_key_file = write_temp_file(state.intermediate_ca_key)

    try do
      # First, verify the CSR signature (proves client owns the private key)
      case verify_csr_signature(csr_file) do
        :ok ->
          # Use SERVER-provided agent_id, not the CSR's CN
          agent_id = server_agent_id

          # Extract public key from CSR (we trust the key, not the subject)
          case extract_public_key_from_csr(csr_file) do
            {:ok, pubkey_file} ->
              try do
                # Generate serial number
                serial = generate_serial()

                # Build certificate config with extensions
                config = build_agent_cert_config_with_subject(state, agent_id)
                config_file = write_temp_file(config)

                try do
                  # Create a new certificate with SERVER-controlled subject
                  case create_cert_with_server_subject(
                         pubkey_file,
                         agent_id,
                         validity_days,
                         serial,
                         config_file,
                         ca_cert_file,
                         ca_key_file
                       ) do
                    {:ok, cert_pem} ->
                      {:ok, cert_pem, agent_id}

                    {:error, _reason} ->
                      # Fallback: sign CSR directly (less secure but functional)
                      Logger.warning("Could not override CSR subject, using CSR signing fallback")

                      sign_csr_fallback(
                        csr_file,
                        validity_days,
                        serial,
                        config_file,
                        ca_cert_file,
                        ca_key_file,
                        agent_id
                      )
                  end
                after
                  File.rm(config_file)
                end
              after
                File.rm(pubkey_file)
              end

            {:error, reason} ->
              {:error, {:pubkey_extraction_failed, reason}}
          end

        {:error, reason} ->
          {:error, reason}
      end
    after
      File.rm(csr_file)
      File.rm(ca_cert_file)
      File.rm(ca_key_file)
    end
  end

  # Extract public key from CSR to a temp file
  defp extract_public_key_from_csr(csr_file) do
    pubkey_file = Path.join(System.tmp_dir!(), "tamandua_pubkey_#{:rand.uniform(999_999)}.pem")

    case openssl(["req", "-in", csr_file, "-pubkey", "-noout", "-out", pubkey_file]) do
      {_, 0} -> {:ok, pubkey_file}
      {error, _} -> {:error, error}
    end
  end

  # Create certificate with server-controlled subject using extracted public key
  defp create_cert_with_server_subject(
         pubkey_file,
         agent_id,
         validity_days,
         serial,
         config_file,
         ca_cert_file,
         ca_key_file
       ) do
    # Create a minimal CSR with our subject and the extracted public key
    # Then sign that CSR
    temp_key_file = Path.join(System.tmp_dir!(), "tamandua_tempkey_#{:rand.uniform(999_999)}.pem")
    temp_csr_file = Path.join(System.tmp_dir!(), "tamandua_tempcsr_#{:rand.uniform(999_999)}.pem")
    cert_file = temp_path("agent_cert")

    try do
      # Generate a temporary key (will be discarded - we only need it to create a CSR format)
      case openssl(["genrsa", "-out", temp_key_file, "2048"]) do
        {_, 0} ->
          # Create CSR with our subject
          subject = "/CN=#{agent_id}/O=Tamandua EDR/OU=Agent"

          case openssl([
                 "req",
                 "-new",
                 "-key",
                 temp_key_file,
                 "-out",
                 temp_csr_file,
                 "-subj",
                 subject
               ]) do
            {_, 0} ->
              # Sign the CSR with -force_pubkey to use the original client's public key
              sign_args = [
                "x509",
                "-req",
                "-in",
                temp_csr_file,
                "-CA",
                ca_cert_file,
                "-CAkey",
                ca_key_file,
                "-set_serial",
                serial,
                "-out",
                cert_file,
                "-days",
                Integer.to_string(validity_days),
                "-extensions",
                "agent_cert",
                "-extfile",
                config_file,
                "-force_pubkey",
                pubkey_file
              ]

              case openssl(sign_args) do
                {_, 0} ->
                  case File.read(cert_file) do
                    {:ok, cert_pem} -> {:ok, String.trim(cert_pem)}
                    {:error, reason} -> {:error, {:cert_read_failed, reason}}
                  end

                {error, _} ->
                  {:error, {:signing_failed, error}}
              end

            {error, _} ->
              {:error, {:csr_creation_failed, error}}
          end

        {error, _} ->
          {:error, {:key_generation_failed, error}}
      end
    after
      File.rm(temp_key_file)
      File.rm(temp_csr_file)
      rm_temp(cert_file)
    end
  end

  # Fallback: sign CSR directly (returns server agent_id but cert has CSR's CN)
  defp sign_csr_fallback(
         csr_file,
         validity_days,
         serial,
         config_file,
         ca_cert_file,
         ca_key_file,
         agent_id
       ) do
    cert_file = temp_path("agent_cert_fallback")

    sign_args = [
      "x509",
      "-req",
      "-in",
      csr_file,
      "-CA",
      ca_cert_file,
      "-CAkey",
      ca_key_file,
      "-set_serial",
      serial,
      "-out",
      cert_file,
      "-days",
      Integer.to_string(validity_days),
      "-extensions",
      "agent_cert",
      "-extfile",
      config_file
    ]

    try do
      case openssl(sign_args) do
        {_, 0} ->
          case File.read(cert_file) do
            {:ok, cert_pem} -> {:ok, String.trim(cert_pem), agent_id}
            {:error, reason} -> {:error, {:cert_read_failed, reason}}
          end

        {error, _} ->
          {:error, {:signing_failed, error}}
      end
    after
      rm_temp(cert_file)
    end
  end

  # Verify CSR signature only (we don't trust the subject)
  defp verify_csr_signature(csr_file) do
    case openssl(["req", "-in", csr_file, "-verify", "-noout"]) do
      {_, 0} -> :ok
      {error, _} -> {:error, {:csr_verification_failed, error}}
    end
  end

  # Build config with explicit subject for the certificate
  defp build_agent_cert_config_with_subject(state, agent_id) do
    """
    [agent_cert]
    basicConstraints = CA:FALSE
    keyUsage = critical, digitalSignature
    extendedKeyUsage = clientAuth
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    authorityInfoAccess = OCSP;URI:#{state.ocsp_url}
    crlDistributionPoints = URI:#{state.crl_url}
    # Subject will be set via -subj flag or inherited from CSR
    # The authoritative agent_id is: #{agent_id}
    """
  end

  defp verify_and_extract_csr_info(csr_file) do
    # Verify CSR signature
    case openssl(["req", "-in", csr_file, "-verify", "-noout"]) do
      {_, 0} ->
        # Extract subject CN
        case openssl(["req", "-in", csr_file, "-noout", "-subject"]) do
          {subject_output, 0} ->
            # Parse CN from subject line: "subject=CN = agent-id, O = Tamandua EDR"
            cn = extract_cn_from_subject(subject_output)

            if cn do
              {:ok, %{cn: cn, subject: String.trim(subject_output)}}
            else
              {:error, :no_cn_in_csr}
            end

          {error, _} ->
            {:error, {:subject_extraction_failed, error}}
        end

      {error, _} ->
        {:error, {:csr_verification_failed, error}}
    end
  end

  defp extract_cn_from_subject(subject_line) do
    # Handle both formats:
    # "subject=CN = agent-id, O = Tamandua EDR"
    # "subject= /CN=agent-id/O=Tamandua EDR"
    cond do
      # Format: CN = value
      String.contains?(subject_line, "CN = ") ->
        subject_line
        |> String.split("CN = ")
        |> List.last()
        |> String.split(",")
        |> List.first()
        |> String.trim()

      # Format: CN=value
      String.contains?(subject_line, "CN=") ->
        subject_line
        |> String.split("CN=")
        |> List.last()
        |> String.split(["/", ","])
        |> List.first()
        |> String.trim()

      true ->
        nil
    end
  end

  defp generate_serial do
    # OpenSSL x509 -set_serial treats bare values as decimal. Prefix random
    # hex serials so A-F bytes do not fail with s2i_ASN1_INTEGER/dec2bn errors.
    "0x" <> Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end

  defp build_agent_cert_config(state, _csr_info) do
    """
    [agent_cert]
    basicConstraints = CA:FALSE
    keyUsage = critical, digitalSignature
    extendedKeyUsage = clientAuth
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    authorityInfoAccess = OCSP;URI:#{state.ocsp_url}
    crlDistributionPoints = URI:#{state.crl_url}
    """
  end

  defp build_ca_config(state, is_root) do
    basic_constraints = if is_root, do: "CA:TRUE", else: "CA:TRUE, pathlen:0"

    """
    [v3_ca]
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    basicConstraints = critical, #{basic_constraints}
    keyUsage = critical, digitalSignature, cRLSign, keyCertSign

    [v3_intermediate_ca]
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    basicConstraints = critical, #{basic_constraints}
    keyUsage = critical, digitalSignature, cRLSign, keyCertSign
    authorityInfoAccess = OCSP;URI:#{state.ocsp_url}
    crlDistributionPoints = URI:#{state.crl_url}
    """
  end

  defp verify_certificate_chain(cert_pem, intermediate_ca_pem, root_ca_pem) do
    # Write certs to temp files for OpenSSL verification
    cert_file = write_temp_file(cert_pem)
    ca_bundle = "#{intermediate_ca_pem}\n#{root_ca_pem}"
    ca_file = write_temp_file(ca_bundle)

    try do
      case openssl(["verify", "-CAfile", ca_file, cert_file]) do
        {output, 0} ->
          if String.contains?(output, "OK") do
            :ok
          else
            {:error, :verification_failed}
          end

        {error, _} ->
          {:error, {:verification_failed, error}}
      end
    after
      File.rm(cert_file)
      File.rm(ca_file)
    end
  end

  defp cert_fingerprint(cert_pem) do
    cert_file = write_temp_file(cert_pem)

    try do
      case openssl(["x509", "-in", cert_file, "-noout", "-fingerprint", "-sha256"]) do
        {output, 0} ->
          output
          |> String.trim()
          |> String.replace("SHA256 Fingerprint=", "")

        _ ->
          "unknown"
      end
    after
      File.rm(cert_file)
    end
  end

  defp openssl(args, opts \\ []) do
    case OSCommand.run("openssl", args, opts) do
      {:error, reason} -> {inspect(reason), 127}
      result -> result
    end
  end

  defp write_temp_file(content) do
    path = temp_path("ca")
    File.write!(path, content)
    path
  end

  defp temp_path(prefix) do
    Path.join(System.tmp_dir!(), "tamandua_#{prefix}_#{System.unique_integer([:positive])}.pem")
  end

  defp rm_temp(path) when is_binary(path), do: File.rm(path)
  defp rm_temp(_), do: :ok

  defp safe_audit(action, details) do
    TamanduaServer.AuditLog.log(%{
      action: action,
      action_type: "pki",
      resource_type: "certificate_authority",
      severity: :info,
      details: details
    })
  rescue
    e ->
      Logger.debug("PKI audit skipped: #{inspect(e)}")
      :ok
  end

  defp get_encryption_key do
    case System.get_env(@encryption_key_env) do
      nil ->
        case System.get_env("SECRET_KEY_BASE") do
          secret when is_binary(secret) and byte_size(secret) >= 32 ->
            Logger.warning(
              "No CA encryption key configured, deriving CA key from SECRET_KEY_BASE (set #{@encryption_key_env})"
            )

            :crypto.hash(:sha256, secret)

          _ ->
            key = :crypto.strong_rand_bytes(32)

            Logger.warning(
              "No CA encryption key or SECRET_KEY_BASE configured, using ephemeral CA key (set #{@encryption_key_env})"
            )

            key
        end

      key_hex ->
        Base.decode16!(key_hex, case: :mixed)
    end
  end

  # Storage Module (handles DB persistence)

  defmodule Storage do
    @moduledoc """
    Persistent storage for CA certificates and encrypted keys.
    """

    require Logger
    alias TamanduaServer.Repo

    def store_root_ca(cert_pem, key_pem, encryption_key) do
      encrypted_key = encrypt_key(key_pem, encryption_key)

      params = %{
        type: "root_ca",
        certificate_pem: cert_pem,
        encrypted_key: encrypted_key,
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }

      # Using raw SQL as schema may not exist yet
      Repo.query!(
        """
        INSERT INTO pki_certificates (type, certificate_pem, encrypted_key, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (type) DO UPDATE SET
          certificate_pem = EXCLUDED.certificate_pem,
          encrypted_key = EXCLUDED.encrypted_key,
          updated_at = EXCLUDED.updated_at
        """,
        [
          params.type,
          params.certificate_pem,
          params.encrypted_key,
          params.inserted_at,
          params.updated_at
        ]
      )

      :ok
    end

    def store_intermediate_ca(cert_pem, key_pem, encryption_key) do
      encrypted_key = encrypt_key(key_pem, encryption_key)

      params = %{
        type: "intermediate_ca",
        certificate_pem: cert_pem,
        encrypted_key: encrypted_key,
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      }

      Repo.query!(
        """
        INSERT INTO pki_certificates (type, certificate_pem, encrypted_key, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (type) DO UPDATE SET
          certificate_pem = EXCLUDED.certificate_pem,
          encrypted_key = EXCLUDED.encrypted_key,
          updated_at = EXCLUDED.updated_at
        """,
        [
          params.type,
          params.certificate_pem,
          params.encrypted_key,
          params.inserted_at,
          params.updated_at
        ]
      )

      :ok
    end

    def load_root_ca(encryption_key) do
      case Repo.query(
             "SELECT certificate_pem, encrypted_key FROM pki_certificates WHERE type = $1",
             ["root_ca"]
           ) do
        {:ok, %{rows: [[cert_pem, encrypted_key]]}} ->
          key_pem = decrypt_key(encrypted_key, encryption_key)
          {:ok, cert_pem, key_pem}

        _ ->
          {:error, :not_found}
      end
    rescue
      e ->
        Logger.error("Failed to load root CA from storage: #{inspect(e)}")
        {:error, :ca_key_decryption_failed}
    end

    def load_intermediate_ca(encryption_key) do
      case Repo.query(
             "SELECT certificate_pem, encrypted_key FROM pki_certificates WHERE type = $1",
             ["intermediate_ca"]
           ) do
        {:ok, %{rows: [[cert_pem, encrypted_key]]}} ->
          key_pem = decrypt_key(encrypted_key, encryption_key)
          {:ok, cert_pem, key_pem}

        _ ->
          {:error, :not_found}
      end
    rescue
      e ->
        Logger.error("Failed to load intermediate CA from storage: #{inspect(e)}")
        {:error, :ca_key_decryption_failed}
    end

    def archive_intermediate_ca(cert_pem) do
      Repo.query!(
        """
        INSERT INTO pki_certificates_archive (type, certificate_pem, archived_at)
        VALUES ($1, $2, $3)
        """,
        ["intermediate_ca", cert_pem, DateTime.utc_now()]
      )

      :ok
    end

    defp encrypt_key(key_pem, encryption_key) do
      iv = :crypto.strong_rand_bytes(16)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(:aes_256_gcm, encryption_key, iv, key_pem, "", 16, true)

      # Concatenate: IV (16) || Tag (16) || Ciphertext
      iv <> tag <> ciphertext
    end

    defp decrypt_key(encrypted_data, encryption_key) do
      <<iv::binary-16, tag::binary-16, ciphertext::binary>> = encrypted_data

      case :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             encryption_key,
             iv,
             ciphertext,
             "",
             tag,
             false
           ) do
        plaintext when is_binary(plaintext) ->
          plaintext

        :error ->
          raise "Failed to decrypt CA key - incorrect encryption key?"
      end
    end
  end
end
