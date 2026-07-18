defmodule TamanduaServer.Enrollment do
  @moduledoc """
  Installation token management and agent enrollment.

  Manages installation tokens that authorize new agent deployments.
  Tokens are hashed with Argon2 and can be scoped to organizations,
  have expiry dates, and usage limits.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Repo.MultiTenant
  alias TamanduaServer.EnrollmentLocatorAccess
  alias TamanduaServer.OSCommand
  alias TamanduaServer.Agents.Agent

  # --------------------------------------------------------------------------
  # Schema
  # --------------------------------------------------------------------------

  defmodule InstallationToken do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id

    schema "installation_tokens" do
      field(:token_hash, :string)
      field(:token_digest, :string)
      field(:name, :string)
      field(:created_by, :string)
      field(:expires_at, :utc_datetime_usec)
      field(:max_uses, :integer)
      field(:use_count, :integer, default: 0)
      field(:revoked, :boolean, default: false)
      field(:last_used_at, :utc_datetime_usec)
      field(:consumed_at, :utc_datetime_usec)
      field(:consumed_agent_id, :binary_id)
      field(:organization_id, :binary_id)

      timestamps()
    end

    def changeset(token, attrs) do
      token
      |> cast(attrs, [
        :token_hash,
        :token_digest,
        :name,
        :created_by,
        :expires_at,
        :max_uses,
        :organization_id,
        :consumed_at,
        :consumed_agent_id
      ])
      |> validate_required([:token_hash])
      |> unique_constraint(:token_hash)
      |> unique_constraint(:token_digest)
    end
  end

  # --------------------------------------------------------------------------
  # Token Generation (Admin)
  # --------------------------------------------------------------------------

  @doc """
  Generate a new installation token.

  Returns `{:ok, cleartext_token, token_record}` — the cleartext token is
  shown to the admin exactly once and is never stored.
  """
  def generate_token(attrs \\ %{}) do
    cleartext = generate_cleartext_token()
    hash = hash_token(cleartext)
    digest = token_digest(cleartext)

    changeset =
      %InstallationToken{}
      |> InstallationToken.changeset(
        attrs
        |> Map.put(:token_hash, hash)
        |> Map.put(:token_digest, digest)
      )

    case Repo.insert(changeset) do
      {:ok, record} -> {:ok, cleartext, record}
      {:error, changeset} -> {:error, changeset}
    end
  end

  @doc """
  List tokens for an organization.
  """
  def list_tokens(organization_id \\ nil) do
    query =
      from(t in InstallationToken,
        order_by: [desc: t.inserted_at]
      )

    query =
      if organization_id do
        from(t in query, where: t.organization_id == ^organization_id)
      else
        query
      end

    Repo.all(query)
  end

  @doc """
  Revoke a token by ID.
  """
  def revoke_token(token_id, organization_id \\ nil) do
    token =
      if organization_id do
        Repo.get_by(InstallationToken, id: token_id, organization_id: organization_id)
      else
        Repo.get(InstallationToken, token_id)
      end

    case token do
      nil ->
        {:error, :not_found}

      token ->
        token
        |> Ecto.Changeset.change(revoked: true)
        |> Repo.update()
    end
  end

  # --------------------------------------------------------------------------
  # Token Validation (Agent Enrollment)
  # --------------------------------------------------------------------------

  @doc """
  Validate an installation token.

  Checks that the token exists, is not revoked, not expired, and has
  remaining uses. Returns `{:ok, token_record}` or `{:error, reason}`.
  """
  def validate_token(cleartext) do
    with {:ok, token_id, organization_id} <- locate_token(cleartext) do
      MultiTenant.with_organization(organization_id, fn ->
        cleartext
        |> lock_exact_token(token_id, organization_id)
        |> validate_locked_token(cleartext)
      end)
      |> normalize_public_result()
    else
      {:error, :persistence_unavailable} -> {:error, :enrollment_unavailable}
      _error -> timing_normalized_invalid_token()
    end
  rescue
    _error -> {:error, :enrollment_unavailable}
  catch
    :exit, _reason -> {:error, :enrollment_unavailable}
  end

  @doc """
  Exchange an installation token for agent credentials.

  Validates the token, increments usage, registers the agent, and
  returns a JWT along with the assigned agent_id and org_id.
  """
  def exchange_token(cleartext, agent_info \\ %{}) do
    do_exchange_token(cleartext, agent_info)
  end

  defp do_exchange_token(cleartext, agent_info) do
    with {:ok, token_id, organization_id} <- locate_token(cleartext) do
      try do
        MultiTenant.with_organization(organization_id, fn ->
          case exchange_in_current_tenant(
                 cleartext,
                 token_id,
                 organization_id,
                 agent_info
               ) do
            {:ok, result} -> result
            {:error, reason} -> throw({:enrollment_exchange_failed, reason})
          end
        end)
        |> then(&{:ok, &1})
      catch
        {:enrollment_exchange_failed, _reason} -> {:error, :invalid_enrollment_token}
      end
    else
      {:error, :persistence_unavailable} -> {:error, :enrollment_unavailable}
      _error -> timing_normalized_invalid_token()
    end
  rescue
    _error -> {:error, :enrollment_unavailable}
  catch
    :exit, _reason -> {:error, :enrollment_unavailable}
  end

  @doc """
  CSR enrollment is unavailable until the Phase 2 durable signing-intent and
  recovery protocol can preserve token and credential atomicity.
  """
  def enroll_with_csr(cleartext, csr_pem, agent_info \\ %{}) do
    _ = {cleartext, csr_pem, agent_info}
    {:error, :enrollment_unavailable}
  end

  @doc """
  Renew an agent's certificate using CSR-based flow.

  This is used when an existing agent needs to renew its certificate.
  The agent is already authenticated via JWT (not installation token).

  ## Parameters

    * `agent_id` - The authenticated agent's ID
    * `csr_pem` - Certificate Signing Request in PEM format

  ## Returns

    * `{:ok, result}` - Success with certificate and optionally updated CA bundle
    * `{:error, reason}` - Error reason
  """
  def renew_certificate_with_csr(agent_id, csr_pem) do
    alias TamanduaServer.PKI.CertificateAuthority

    # Verify CSR CN matches the authenticated agent_id
    case extract_cn_from_csr(csr_pem) do
      {:error, reason} ->
        {:error, reason}

      {:ok, csr_agent_id} when csr_agent_id != agent_id ->
        {:error, :agent_id_mismatch}

      {:ok, ^agent_id} ->
        case CertificateAuthority.ensure_initialized() do
          :ok ->
            case CertificateAuthority.sign_csr(csr_pem, validity_days: 90, agent_id: agent_id) do
              {:error, reason} ->
                {:error, {:signing_failed, reason}}

              {:ok, cert_pem, ^agent_id} ->
                # Get CA bundle (may have been rotated)
                ca_bundle = effective_agent_ca_bundle()

                {:ok,
                 %{
                   certificate: cert_pem,
                   ca_bundle: ca_bundle
                 }}
            end

          {:error, reason} ->
            {:error, {:pki_not_ready, reason}}
        end
    end
  end

  # --------------------------------------------------------------------------
  # Private Helpers
  # --------------------------------------------------------------------------

  defp locate_token(cleartext)
       when is_binary(cleartext) and byte_size(cleartext) >= 1 and byte_size(cleartext) <= 512 do
    cleartext
    |> token_digest()
    |> EnrollmentLocatorAccess.locate()
  end

  defp locate_token(_cleartext), do: {:error, :invalid_enrollment_token}

  defp lock_exact_token(cleartext, token_id, organization_id) do
    digest = token_digest(cleartext)

    from(t in InstallationToken,
      where:
        t.id == ^token_id and t.organization_id == ^organization_id and
          t.token_digest == ^digest,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp validate_locked_token(nil, _cleartext), do: {:error, :invalid_enrollment_token}

  defp validate_locked_token(%InstallationToken{} = token, cleartext) do
    # Verify the expensive secret first so revoked/expired/exhausted states are
    # not distinguishable from a wrong bearer token through this public API.
    if verify_hash(cleartext, token.token_hash) do
      if valid_token_state?(token),
        do: {:ok, token},
        else: {:error, :invalid_enrollment_token}
    else
      {:error, :invalid_enrollment_token}
    end
  end

  defp valid_token_state?(token) do
    token.revoked == false and not token_expired?(token) and not token_exhausted?(token) and
      is_binary(token.organization_id)
  end

  defp exchange_in_current_tenant(cleartext, token_id, organization_id, agent_info) do
    with %InstallationToken{} = token <-
           lock_exact_token(cleartext, token_id, organization_id),
         {:ok, ^token} <- validate_locked_token(token, cleartext),
         agent_id <- Ecto.UUID.generate(),
         :ok <- register_agent(agent_id, organization_id, agent_info),
         %Agent{} = locked_agent <- lock_exact_agent(agent_id, organization_id),
         {:ok, jwt, _token_record} <-
           TamanduaServer.Agents.TokenManager.issue_token_in_current_tenant(locked_agent),
         {:ok, _consumed_token} <- consume_locked_token(token, agent_id) do
      {:ok, %{agent_id: agent_id, jwt: jwt, org_id: organization_id}}
    else
      _error -> {:error, :invalid_enrollment_token}
    end
  end

  defp lock_exact_agent(agent_id, organization_id) do
    from(a in Agent,
      where: a.id == ^agent_id and a.organization_id == ^organization_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp consume_locked_token(%InstallationToken{} = token, agent_id) do
    now = DateTime.utc_now()

    token
    |> Ecto.Changeset.change(
      use_count: token.use_count + 1,
      last_used_at: now,
      consumed_at: now,
      consumed_agent_id: agent_id
    )
    |> Repo.update()
  end

  defp normalize_public_result({:ok, %InstallationToken{} = token}), do: {:ok, token}
  defp normalize_public_result(_result), do: {:error, :invalid_enrollment_token}

  defp timing_normalized_invalid_token do
    Argon2.no_user_verify()
    {:error, :invalid_enrollment_token}
  end

  defp effective_agent_ca_bundle do
    file_bundle =
      [
        System.get_env("AGENT_MTLS_CLIENT_CA_CERTFILE"),
        System.get_env("CA_CERT_PATH")
      ]
      |> Enum.find_value(fn
        nil -> nil
        "" -> nil
        path -> read_pem_bundle(path)
      end)

    pki_bundle =
      case TamanduaServer.PKI.CertificateAuthority.export_for_agents() do
        {:ok, export} -> export.ca_bundle_pem
        _ -> nil
      end

    [file_bundle, pki_bundle]
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
    |> Enum.join("\n")
  end

  defp read_pem_bundle(path) do
    case File.read(path) do
      {:ok, pem} ->
        if String.contains?(pem, "BEGIN CERTIFICATE"), do: pem, else: nil

      {:error, _reason} ->
        nil
    end
  end

  defp extract_cn_from_csr(csr_pem) do
    # Write CSR to temp file
    temp_path = Path.join(System.tmp_dir!(), "tamandua_csr_#{:rand.uniform(999_999)}.pem")
    File.write!(temp_path, csr_pem)

    try do
      # Extract subject from CSR
      case openssl(["req", "-in", temp_path, "-noout", "-subject"]) do
        {subject_output, 0} ->
          # Parse CN from subject line
          cn = parse_cn_from_subject(subject_output)

          if cn do
            {:ok, cn}
          else
            {:error, :no_cn_in_csr}
          end

        {:error, reason} ->
          {:error, reason}

        {_error, _} ->
          {:error, :invalid_csr}
      end
    after
      File.rm(temp_path)
    end
  end

  defp parse_cn_from_subject(subject_line) do
    cond do
      String.contains?(subject_line, "CN = ") ->
        subject_line
        |> String.split("CN = ")
        |> List.last()
        |> String.split(",")
        |> List.first()
        |> String.trim()

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

  defp generate_cleartext_token do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end

  defp hash_token(cleartext) do
    Argon2.hash_pwd_salt(cleartext)
  end

  defp token_digest(cleartext) do
    :crypto.hash(:sha256, cleartext)
    |> Base.encode16(case: :lower)
  end

  defp verify_hash(cleartext, hash) do
    Argon2.verify_pass(cleartext, hash)
  end

  defp token_expired?(%{expires_at: nil}), do: false

  defp token_expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp token_exhausted?(%{max_uses: nil}), do: false

  defp token_exhausted?(%{max_uses: max, use_count: count}) do
    count >= max
  end

  defp register_agent(agent_id, org_id, agent_info) do
    # Insert into agents table. This is a minimal registration;
    # the agent will update its full profile on first connection.
    now = DateTime.utc_now()
    hostname = Map.get(agent_info, "hostname", "unknown")
    os_type = Map.get(agent_info, "os_type") || Map.get(agent_info, "os") || "unknown"
    os_version = Map.get(agent_info, "os_version", "")
    agent_version = Map.get(agent_info, "agent_version", "")
    machine_id = Map.get(agent_info, "machine_id")

    attrs = %{
      id: dump_uuid!(agent_id),
      hostname: hostname,
      os_type: os_type,
      os_version: os_version,
      agent_version: agent_version,
      machine_id: machine_id,
      status: "registered",
      organization_id: dump_uuid!(org_id),
      last_seen_at: now,
      token_rotation_enabled: true,
      token_ttl_hours: 720,
      token_refresh_window_percent: 60,
      current_token_generation: 0,
      inserted_at: now,
      updated_at: now,
      config: %{
        "enrolled_at" => DateTime.to_iso8601(now),
        "arch" => Map.get(agent_info, "arch", ""),
        "os_name" => Map.get(agent_info, "os_name"),
        "os_build" => Map.get(agent_info, "os_build"),
        "domain" => Map.get(agent_info, "domain"),
        "install_path" => Map.get(agent_info, "install_path")
      }
    }

    config = attrs.config

    conflict_update =
      from(a in Agent,
        where: a.organization_id == ^org_id,
        update: [
          set: [
            hostname: ^hostname,
            os_type: ^os_type,
            os_version: ^os_version,
            agent_version: ^agent_version,
            machine_id: ^machine_id,
            status: "registered",
            last_seen_at: ^now,
            token_rotation_enabled: true,
            token_ttl_hours: 720,
            token_refresh_window_percent: 60,
            updated_at: ^now,
            config: ^config
          ]
        ]
      )

    case Repo.insert_all("agents", [attrs],
           on_conflict: conflict_update,
           conflict_target: [:id]
         ) do
      {1, _rows} ->
        :ok

      {0, _rows} ->
        {:error, :organization_mismatch}

      {count, _rows} ->
        {:error, {:unexpected_registration_count, count}}
    end
  rescue
    e ->
      require Logger
      Logger.error("Agent registration failed: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp dump_uuid!(uuid) when is_binary(uuid) do
    case Ecto.UUID.dump(uuid) do
      {:ok, dumped} -> dumped
      :error -> raise ArgumentError, "invalid UUID: #{inspect(uuid)}"
    end
  end

  defp openssl(args) do
    OSCommand.run("openssl", args)
  end
end
