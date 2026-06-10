defmodule TamanduaServer.PKI.RevocationList do
  @moduledoc """
  Certificate Revocation List (CRL) management.

  Manages the X.509 CRL for revoked agent certificates. The CRL is:

  - Signed by the intermediate CA
  - Updated whenever a certificate is revoked
  - Served via HTTP for agent verification
  - Regenerated periodically (daily) to update NextUpdate field
  - Stored in database and cached in memory

  CRL Format: DER-encoded X.509 CRL v2

  ## CRL Distribution

  The CRL is published at the URL configured in certificates:
  `crlDistributionPoints = URI:http://crl.tamandua.local/crl.pem`

  Agents download and cache the CRL, checking it before accepting
  server connections.

  ## Example

      # Revoke a certificate
      :ok = RevocationList.revoke_certificate("ABC123", :key_compromise)

      # Check revocation status
      case RevocationList.is_revoked?("ABC123") do
        :ok -> # Not revoked
        {:error, :revoked} -> # Revoked
      end

      # Get current CRL for distribution
      {:ok, crl_der} = RevocationList.get_current_crl()

      # Force CRL regeneration
      :ok = RevocationList.regenerate_crl()
  """

  use GenServer
  require Logger
  alias TamanduaServer.OSCommand
  alias TamanduaServer.PKI.CertificateAuthority
  alias TamanduaServer.Audit
  alias TamanduaServer.Repo

  # CRL valid for 24 hours
  @crl_validity_hours 24
  # Regenerate every 12 hours
  @regeneration_interval_hours 12

  defmodule State do
    @moduledoc false
    defstruct [
      :current_crl_der,
      :current_crl_number,
      :last_generated_at,
      # MapSet for fast lookup
      :revoked_serials,
      :cached_crl_pem
    ]
  end

  # Client API

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Revoke a certificate by serial number.

  ## Revocation Reasons

  - `:unspecified` - General revocation (default)
  - `:key_compromise` - Private key compromised
  - `:ca_compromise` - CA private key compromised (rare, full re-issuance needed)
  - `:affiliation_changed` - Agent moved to different organization
  - `:superseded` - Certificate replaced by new one
  - `:cessation_of_operation` - Agent decommissioned
  - `:certificate_hold` - Temporary suspension (can be unrevoked)
  - `:remove_from_crl` - Remove from CRL (only valid for :certificate_hold)
  - `:privilege_withdrawn` - Agent lost authorization
  - `:aa_compromise` - Attribute authority compromised

  ## Returns

  - `:ok` - Certificate revoked and CRL updated
  - `{:error, :already_revoked}` - Certificate was already revoked
  - `{:error, reason}` - Other errors
  """
  def revoke_certificate(serial_number, reason \\ :unspecified) do
    GenServer.call(__MODULE__, {:revoke, serial_number, reason})
  end

  @doc """
  Unrevoke a certificate (only allowed for certificates on hold).

  This removes the certificate from the CRL. Only valid if the
  revocation reason was `:certificate_hold`.
  """
  def unrevoke_certificate(serial_number) do
    GenServer.call(__MODULE__, {:unrevoke, serial_number})
  end

  @doc """
  Check if a certificate is revoked.

  ## Returns

  - `:ok` - Certificate is not revoked
  - `{:error, :revoked}` - Certificate is revoked
  """
  def is_revoked?(serial_number) do
    GenServer.call(__MODULE__, {:is_revoked, serial_number})
  end

  @doc """
  Get the current CRL in DER format.

  Returns `{:ok, crl_der}` with the binary DER-encoded CRL.
  """
  def get_current_crl do
    GenServer.call(__MODULE__, :get_current_crl)
  end

  @doc """
  Get the current CRL in PEM format.

  Returns `{:ok, crl_pem}` with the PEM-encoded CRL.
  """
  def get_current_crl_pem do
    GenServer.call(__MODULE__, :get_current_crl_pem)
  end

  @doc """
  Force immediate CRL regeneration.

  Useful after revoking certificates to ensure CRL is up-to-date.
  """
  def regenerate_crl do
    GenServer.cast(__MODULE__, :regenerate_crl)
  end

  @doc """
  Get CRL statistics.

  Returns:
  - `total_revoked` - Total number of revoked certificates
  - `crl_number` - Current CRL sequence number
  - `last_generated_at` - Timestamp of last CRL generation
  - `next_update` - When CRL expires
  """
  def get_stats do
    GenServer.call(__MODULE__, :get_stats)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    Logger.info("Certificate Revocation List initialized")

    # Load revoked certificates from database
    revoked_serials = load_revoked_serials()

    # Load or generate initial CRL
    state = %State{
      current_crl_der: nil,
      current_crl_number: get_next_crl_number(),
      last_generated_at: nil,
      revoked_serials: revoked_serials,
      cached_crl_pem: nil
    }

    # Generate initial CRL
    state = generate_crl(state)

    # Schedule periodic regeneration
    schedule_regeneration()

    {:ok, state}
  end

  @impl true
  def handle_call({:revoke, serial_number, reason}, _from, state) do
    if MapSet.member?(state.revoked_serials, serial_number) do
      {:reply, {:error, :already_revoked}, state}
    else
      Logger.info("Revoking certificate", serial: serial_number, reason: reason)

      # Add to database
      :ok = store_revocation(serial_number, reason)

      # Update in-memory set
      new_revoked = MapSet.put(state.revoked_serials, serial_number)

      # Regenerate CRL
      new_state = %{state | revoked_serials: new_revoked}
      new_state = generate_crl(new_state)

      # Audit log
      Audit.log("pki.certificate_revoked", %{
        serial_number: serial_number,
        reason: reason,
        crl_number: new_state.current_crl_number
      })

      {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_call({:unrevoke, serial_number}, _from, state) do
    if MapSet.member?(state.revoked_serials, serial_number) do
      # Check if revocation reason allows unrevocation
      case get_revocation_reason(serial_number) do
        {:ok, :certificate_hold} ->
          Logger.info("Unrevoking certificate", serial: serial_number)

          # Remove from database
          :ok = remove_revocation(serial_number)

          # Update in-memory set
          new_revoked = MapSet.delete(state.revoked_serials, serial_number)

          # Regenerate CRL
          new_state = %{state | revoked_serials: new_revoked}
          new_state = generate_crl(new_state)

          Audit.log("pki.certificate_unrevoked", %{
            serial_number: serial_number,
            crl_number: new_state.current_crl_number
          })

          {:reply, :ok, new_state}

        {:ok, other_reason} ->
          {:reply, {:error, {:cannot_unrevoke, other_reason}}, state}

        {:error, _} ->
          {:reply, {:error, :not_revoked}, state}
      end
    else
      {:reply, {:error, :not_revoked}, state}
    end
  end

  @impl true
  def handle_call({:is_revoked, serial_number}, _from, state) do
    if MapSet.member?(state.revoked_serials, serial_number) do
      {:reply, {:error, :revoked}, state}
    else
      {:reply, :ok, state}
    end
  end

  @impl true
  def handle_call(:get_current_crl, _from, state) do
    case state.current_crl_der do
      nil -> {:reply, {:error, :crl_not_available}, state}
      crl_der -> {:reply, {:ok, crl_der}, state}
    end
  end

  @impl true
  def handle_call(:get_current_crl_pem, _from, state) do
    case state.cached_crl_pem do
      nil ->
        # Convert DER to PEM
        case der_to_pem(state.current_crl_der) do
          {:ok, pem} ->
            new_state = %{state | cached_crl_pem: pem}
            {:reply, {:ok, pem}, new_state}

          error ->
            {:reply, error, state}
        end

      pem ->
        {:reply, {:ok, pem}, state}
    end
  end

  @impl true
  def handle_call(:get_stats, _from, state) do
    stats = %{
      total_revoked: MapSet.size(state.revoked_serials),
      crl_number: state.current_crl_number,
      last_generated_at: state.last_generated_at,
      next_update: calculate_next_update(state.last_generated_at)
    }

    {:reply, stats, state}
  end

  @impl true
  def handle_cast(:regenerate_crl, state) do
    Logger.info("Manual CRL regeneration triggered")
    new_state = generate_crl(state)
    {:noreply, new_state}
  end

  @impl true
  def handle_info(:regenerate_crl_scheduled, state) do
    Logger.info("Scheduled CRL regeneration")
    new_state = generate_crl(state)

    # Schedule next regeneration
    schedule_regeneration()

    {:noreply, new_state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # Private Functions

  defp generate_crl(state) do
    Logger.info("Generating new CRL", revoked_count: MapSet.size(state.revoked_serials))

    # Get CA certificate and key
    with {:ok, ca_cert_pem} <- CertificateAuthority.get_intermediate_ca_cert(),
         {:ok, ca_key_pem} <- get_ca_private_key() do
      # Build CRL configuration
      crl_config = build_crl_config(state)
      config_file = write_temp_file(crl_config)

      # Write CA cert and key to temp files
      ca_cert_file = write_temp_file(ca_cert_pem)
      ca_key_file = write_temp_file(ca_key_pem)

      try do
        # Generate CRL using OpenSSL
        args = [
          "ca",
          "-gencrl",
          "-cert",
          ca_cert_file,
          "-keyfile",
          ca_key_file,
          "-out",
          "/dev/stdout",
          "-config",
          config_file,
          "-crldays",
          Integer.to_string(div(@crl_validity_hours, 24))
        ]

        case openssl(args) do
          {crl_pem, 0} ->
            # Convert PEM to DER
            case pem_to_der(crl_pem) do
              {:ok, crl_der} ->
                # Store CRL in database
                :ok = store_crl(crl_der, state.current_crl_number)

                Logger.info("CRL generated successfully", crl_number: state.current_crl_number)

                %{
                  state
                  | current_crl_der: crl_der,
                    last_generated_at: DateTime.utc_now(),
                    cached_crl_pem: String.trim(crl_pem),
                    current_crl_number: state.current_crl_number + 1
                }

              {:error, reason} ->
                Logger.error("Failed to convert CRL to DER", reason: inspect(reason))
                state
            end

          {error, _} ->
            Logger.error("Failed to generate CRL", error: error)
            state
        end
      after
        File.rm(config_file)
        File.rm(ca_cert_file)
        File.rm(ca_key_file)
      end
    else
      {:error, reason} ->
        Logger.error("Failed to get CA credentials for CRL generation", reason: inspect(reason))
        state
    end
  end

  defp build_crl_config(state) do
    # Build OpenSSL config for CRL generation
    # Include all revoked certificates

    revoked_entries =
      state.revoked_serials
      |> Enum.map(fn serial ->
        case get_revocation_details(serial) do
          {:ok, details} ->
            # Format: serial = reason,date
            "#{serial} = #{reason_code(details.reason)},#{format_revocation_date(details.revoked_at)}"

          {:error, _} ->
            # Fallback if details not found
            "#{serial} = unspecified,#{format_revocation_date(DateTime.utc_now())}"
        end
      end)
      |> Enum.join("\n")

    """
    [ ca ]
    default_ca = CA_default

    [ CA_default ]
    database = /dev/null
    crlnumber = /dev/stdout

    [ crl_ext ]
    # CRL extensions
    authorityKeyIdentifier=keyid:always
    """ <>
      if String.length(revoked_entries) > 0, do: "\n[revoked]\n#{revoked_entries}", else: ""
  end

  defp reason_code(reason) do
    case reason do
      :unspecified -> "unspecified"
      :key_compromise -> "keyCompromise"
      :ca_compromise -> "CACompromise"
      :affiliation_changed -> "affiliationChanged"
      :superseded -> "superseded"
      :cessation_of_operation -> "cessationOfOperation"
      :certificate_hold -> "certificateHold"
      :remove_from_crl -> "removeFromCRL"
      :privilege_withdrawn -> "privilegeWithdrawn"
      :aa_compromise -> "AACompromise"
      _ -> "unspecified"
    end
  end

  defp format_revocation_date(datetime) do
    # Format as ASN.1 GeneralizedTime: YYYYMMDDhhmmssZ
    datetime
    |> DateTime.to_naive()
    |> NaiveDateTime.to_string()
    |> String.replace(~r/[^0-9]/, "")
    |> String.slice(0, 14)
    |> Kernel.<>("Z")
  end

  defp pem_to_der(pem) do
    pem_file = write_temp_file(pem)

    try do
      case openssl(["crl", "-in", pem_file, "-outform", "DER", "-out", "/dev/stdout"]) do
        {der, 0} -> {:ok, der}
        {error, _} -> {:error, {:conversion_failed, error}}
      end
    after
      File.rm(pem_file)
    end
  end

  defp der_to_pem(der) do
    der_file = write_temp_file(der)

    try do
      case openssl(["crl", "-in", der_file, "-inform", "DER", "-out", "/dev/stdout"]) do
        {pem, 0} -> {:ok, String.trim(pem)}
        {error, _} -> {:error, {:conversion_failed, error}}
      end
    after
      File.rm(der_file)
    end
  end

  defp load_revoked_serials do
    query = "SELECT serial_number FROM certificate_revocations WHERE status = 'revoked'"

    case Repo.query(query) do
      {:ok, %{rows: rows}} ->
        rows
        |> Enum.map(fn [serial] -> serial end)
        |> MapSet.new()

      {:error, _} ->
        MapSet.new()
    end
  end

  defp store_revocation(serial_number, reason) do
    params = [
      serial_number,
      to_string(reason),
      DateTime.utc_now(),
      DateTime.utc_now(),
      "revoked"
    ]

    Repo.query!(
      """
      INSERT INTO certificate_revocations (serial_number, reason, revoked_at, updated_at, status)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (serial_number) DO UPDATE SET
        reason = EXCLUDED.reason,
        revoked_at = EXCLUDED.revoked_at,
        status = EXCLUDED.status,
        updated_at = EXCLUDED.updated_at
      """,
      params
    )

    :ok
  end

  defp remove_revocation(serial_number) do
    Repo.query!(
      "UPDATE certificate_revocations SET status = 'removed', updated_at = $1 WHERE serial_number = $2",
      [DateTime.utc_now(), serial_number]
    )

    :ok
  end

  defp get_revocation_reason(serial_number) do
    case Repo.query("SELECT reason FROM certificate_revocations WHERE serial_number = $1", [
           serial_number
         ]) do
      {:ok, %{rows: [[reason]]}} ->
        {:ok, String.to_existing_atom(reason)}

      _ ->
        {:error, :not_found}
    end
  end

  defp get_revocation_details(serial_number) do
    case Repo.query(
           "SELECT reason, revoked_at FROM certificate_revocations WHERE serial_number = $1",
           [serial_number]
         ) do
      {:ok, %{rows: [[reason, revoked_at]]}} ->
        {:ok, %{reason: String.to_existing_atom(reason), revoked_at: revoked_at}}

      _ ->
        {:error, :not_found}
    end
  end

  defp store_crl(crl_der, crl_number) do
    Repo.query!(
      """
      INSERT INTO certificate_revocation_lists (crl_number, crl_der, generated_at)
      VALUES ($1, $2, $3)
      """,
      [crl_number, crl_der, DateTime.utc_now()]
    )

    :ok
  end

  defp get_next_crl_number do
    case Repo.query("SELECT MAX(crl_number) FROM certificate_revocation_lists") do
      {:ok, %{rows: [[nil]]}} -> 1
      {:ok, %{rows: [[max_number]]}} -> max_number + 1
      _ -> 1
    end
  end

  defp get_ca_private_key do
    # Retrieve intermediate CA private key
    GenServer.call(TamanduaServer.PKI.CertificateAuthority, :get_intermediate_ca_key)
  end

  defp calculate_next_update(nil), do: nil

  defp calculate_next_update(last_generated_at) do
    DateTime.add(last_generated_at, @crl_validity_hours * 3600, :second)
  end

  defp schedule_regeneration do
    Process.send_after(
      self(),
      :regenerate_crl_scheduled,
      @regeneration_interval_hours * 3600 * 1000
    )
  end

  defp write_temp_file(content) do
    path = Path.join(System.tmp_dir!(), "tamandua_crl_#{:rand.uniform(999_999)}")
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
