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
  alias TamanduaServer.OSCommand
  alias TamanduaServer.Agents.{Agent, AgentCredential}
  alias TamanduaServer.Agents.TokenManager.AgentToken

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
    with_enrollment_bypass(fn -> do_validate_token(cleartext) end)
  end

  defp do_validate_token(cleartext) do
    digest = token_digest(cleartext)

    token =
      from(t in InstallationToken,
        where:
          t.revoked == false and
            t.token_digest == ^digest
      )
      |> Repo.one()

    case token do
      nil ->
        {:error, "Invalid token"}

      token ->
        validate_installation_token_record(cleartext, token)
    end
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
    case validate_token(cleartext) do
      {:error, reason} ->
        {:error, reason}

      {:ok, token} ->
        if is_nil(token.organization_id) do
          {:error, "Installation token is not bound to an organization"}
        else
          # Generate agent credentials
          agent_id = Ecto.UUID.generate()

          case consume_token_for_registration(cleartext, token.id, agent_id, agent_info) do
            {:ok, org_id} ->
              case generate_agent_jwt(agent_id, org_id) do
                {:ok, jwt} ->
                  case finalize_token_use(cleartext, token.id, agent_id) do
                    :ok ->
                      {:ok,
                       %{
                         agent_id: agent_id,
                         jwt: jwt,
                         org_id: org_id
                       }}

                    {:error, reason} ->
                      cleanup_failed_enrollment(agent_id)
                      {:error, reason}
                  end

                {:error, reason} ->
                  cleanup_failed_enrollment(agent_id)
                  {:error, {:credential_issuance_failed, reason}}
              end

            {:error, {:agent_registration_failed, reason}} ->
              {:error, {:agent_registration_failed, reason}}

            {:error, reason} ->
              {:error, reason}
          end
        end
    end
  end

  @doc """
  Enroll an agent using CSR-based flow (private key never leaves agent).

  This is the secure enrollment flow where:
  1. Agent generates RSA keypair locally
  2. Agent sends CSR (containing public key) to server
  3. Server generates agent_id for new installs, or accepts the existing
     agent_id only for same-agent recovery
  4. Server signs CSR with the server-approved agent_id as CN
  5. Server returns signed certificate + CA bundle

  ## Security

  The server generates the agent_id for first-time enrollment. Existing agent_id
  recovery is only accepted when the installation token was previously consumed
  by that same agent, which allows unattended credential recovery without letting
  exhausted tokens create arbitrary agents.

  ## Parameters

    * `cleartext` - Installation token for authorization
    * `csr_pem` - Certificate Signing Request in PEM format
    * `agent_info` - Agent system information map

  ## Returns

    * `{:ok, result}` - Success with certificate, CA bundle, JWT, and agent_id
    * `{:error, reason}` - Error reason
  """
  def enroll_with_csr(cleartext, csr_pem, agent_info \\ %{}) do
    do_enroll_with_csr(cleartext, csr_pem, agent_info)
  end

  defp do_enroll_with_csr(cleartext, csr_pem, agent_info) do
    alias TamanduaServer.PKI.CertificateAuthority

    case validate_csr_enrollment_token(cleartext, agent_info) do
      {:error, reason} ->
        {:error, reason}

      {:ok, token, mode} ->
        if is_nil(token.organization_id) do
          {:error, "Installation token is not bound to an organization"}
        else
          # Validate CSR format (but ignore the CN - we generate our own agent_id)
          case validate_csr_format(csr_pem) do
            {:error, reason} ->
              {:error, reason}

            :ok ->
              agent_id = csr_enrollment_agent_id(mode)

              case CertificateAuthority.ensure_initialized() do
                :ok ->
                  # Sign the CSR with the server-approved agent_id as the CN.
                  case CertificateAuthority.sign_csr(csr_pem,
                         validity_days: 90,
                         agent_id: agent_id
                       ) do
                    {:error, reason} ->
                      {:error, {:signing_failed, reason}}

                    {:ok, cert_pem, ^agent_id} ->
                      case prepare_csr_agent_registration(
                             cleartext,
                             token,
                             agent_id,
                             agent_info,
                             mode
                           ) do
                        {:ok, org_id} ->
                          case generate_agent_jwt(agent_id, org_id) do
                            {:ok, jwt} ->
                              case finalize_csr_token_use(cleartext, token, agent_id, mode) do
                                :ok ->
                                  ca_bundle = effective_agent_ca_bundle()

                                  {:ok,
                                   %{
                                     agent_id: agent_id,
                                     jwt: jwt,
                                     org_id: org_id,
                                     certificate: cert_pem,
                                     ca_bundle: ca_bundle
                                   }}

                                {:error, reason} ->
                                  cleanup_failed_enrollment(agent_id)
                                  {:error, reason}
                              end

                            {:error, reason} ->
                              cleanup_failed_enrollment(agent_id)
                              {:error, {:credential_issuance_failed, reason}}
                          end

                        {:error, {:agent_registration_failed, reason}} ->
                          {:error, {:agent_registration_failed, reason}}

                        {:error, reason} ->
                          {:error, reason}
                      end
                  end

                {:error, reason} ->
                  {:error, {:pki_not_ready, reason}}
              end
          end
        end
    end
  end

  defp with_enrollment_bypass(fun) do
    MultiTenant.with_bypass(fun)
  rescue
    e ->
      require Logger

      Logger.error("""
      Enrollment failed during trusted system operation
      #{Exception.format(:error, e, __STACKTRACE__)}
      """)

      {:error, {:enrollment_failed, :internal_error}}
  end

  defp validate_csr_enrollment_token(cleartext, agent_info) do
    case validate_token(cleartext) do
      {:ok, token} ->
        {:ok, token, :new_enrollment}

      {:error, "Token has reached its maximum number of uses"} ->
        validate_csr_recovery_token(cleartext, requested_agent_id(agent_info))

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_csr_recovery_token(_cleartext, nil), do: {:error, "Invalid token"}

  defp validate_csr_recovery_token(cleartext, requested_agent_id) do
    with_enrollment_bypass(fn ->
      digest = token_digest(cleartext)

      token =
        from(t in InstallationToken,
          where:
            t.revoked == false and
              t.token_digest == ^digest
        )
        |> Repo.one()

      case token do
        nil ->
          {:error, "Invalid token"}

        token ->
          cond do
            token_expired?(token) ->
              {:error, "Token has expired"}

            token.consumed_agent_id != requested_agent_id ->
              {:error, "Token has reached its maximum number of uses"}

            !verify_hash(cleartext, token.token_hash) ->
              {:error, "Invalid token"}

            !agent_exists_for_token_org?(requested_agent_id, token.organization_id) ->
              {:error, "Agent not found for recovery token"}

            true ->
              {:ok, token, {:recovery, requested_agent_id}}
          end
      end
    end)
  end

  defp requested_agent_id(agent_info) when is_map(agent_info) do
    case Map.get(agent_info, "agent_id") do
      value when is_binary(value) ->
        value = String.trim(value)

        case Ecto.UUID.cast(value) do
          {:ok, uuid} -> uuid
          :error -> nil
        end

      _ ->
        nil
    end
  end

  defp requested_agent_id(_), do: nil

  defp agent_exists_for_token_org?(agent_id, org_id)
       when is_binary(agent_id) and is_binary(org_id) do
    case Repo.get_by(Agent, id: agent_id, organization_id: org_id) do
      nil -> false
      _agent -> true
    end
  end

  defp agent_exists_for_token_org?(_, _), do: false

  defp csr_enrollment_agent_id(:new_enrollment), do: Ecto.UUID.generate()
  defp csr_enrollment_agent_id({:recovery, agent_id}), do: agent_id

  defp prepare_csr_agent_registration(cleartext, token, agent_id, agent_info, :new_enrollment) do
    consume_token_for_registration(cleartext, token.id, agent_id, agent_info)
  end

  defp prepare_csr_agent_registration(_cleartext, token, agent_id, agent_info, {:recovery, _}) do
    case register_agent(agent_id, token.organization_id, agent_info) do
      :ok -> {:ok, token.organization_id}
      {:error, reason} -> {:error, {:agent_registration_failed, reason}}
    end
  end

  defp finalize_csr_token_use(cleartext, token, agent_id, :new_enrollment) do
    finalize_token_use(cleartext, token.id, agent_id)
  end

  defp finalize_csr_token_use(_cleartext, token, agent_id, {:recovery, _}) do
    finalize_recovery_token_use(token.id, agent_id)
  end

  defp finalize_recovery_token_use(token_id, agent_id) do
    with_enrollment_bypass(fn ->
      Repo.transaction(fn ->
        token =
          from(t in InstallationToken,
            where: t.id == ^token_id,
            lock: "FOR UPDATE"
          )
          |> Repo.one()

        case token do
          nil ->
            Repo.rollback("Invalid token")

          token ->
            token
            |> Ecto.Changeset.change(
              last_used_at: DateTime.utc_now(),
              consumed_at: token.consumed_at || DateTime.utc_now(),
              consumed_agent_id: agent_id
            )
            |> Repo.update!()

            :ok
        end
      end)
      |> case do
        {:ok, :ok} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  # Validate CSR format without trusting the CN
  defp validate_csr_format(csr_pem) do
    temp_path =
      Path.join(System.tmp_dir!(), "tamandua_csr_validate_#{:rand.uniform(999_999)}.pem")

    File.write!(temp_path, csr_pem)

    try do
      # Verify CSR signature (proves client has private key)
      case openssl(["req", "-in", temp_path, "-verify", "-noout"]) do
        {_, 0} -> :ok
        {:error, reason} -> {:error, reason}
        {_error, _} -> {:error, :invalid_csr_signature}
      end
    after
      File.rm(temp_path)
    end
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

  defp validate_installation_token_record(cleartext, token) do
    cond do
      token_expired?(token) ->
        {:error, "Token has expired"}

      token_exhausted?(token) ->
        {:error, "Token has reached its maximum number of uses"}

      !verify_hash(cleartext, token.token_hash) ->
        {:error, "Invalid token"}

      true ->
        {:ok, token}
    end
  end

  defp token_expired?(%{expires_at: nil}), do: false

  defp token_expired?(%{expires_at: expires_at}) do
    DateTime.compare(DateTime.utc_now(), expires_at) == :gt
  end

  defp token_exhausted?(%{max_uses: nil}), do: false

  defp token_exhausted?(%{max_uses: max, use_count: count}) do
    count >= max
  end

  defp consume_token_for_registration(cleartext, token_id, agent_id, agent_info) do
    with_enrollment_bypass(fn ->
      Repo.transaction(fn ->
        token =
          from(t in InstallationToken,
            where: t.id == ^token_id,
            lock: "FOR UPDATE"
          )
          |> Repo.one()

        case token do
          nil ->
            Repo.rollback("Invalid token")

          token ->
            case validate_installation_token_record(cleartext, token) do
              {:error, reason} ->
                Repo.rollback(reason)

              {:ok, token} ->
                org_id = token.organization_id

                case register_agent(agent_id, org_id, agent_info) do
                  :ok ->
                    org_id

                  {:error, reason} ->
                    Repo.rollback({:agent_registration_failed, reason})
                end
            end
        end
      end)
      |> case do
        {:ok, org_id} -> {:ok, org_id}
        {:error, reason} -> {:error, reason}
      end
    end)
  end

  defp finalize_token_use(cleartext, token_id, agent_id) do
    with_enrollment_bypass(fn ->
      Repo.transaction(fn ->
        token =
          from(t in InstallationToken,
            where: t.id == ^token_id,
            lock: "FOR UPDATE"
          )
          |> Repo.one()

        case token do
          nil ->
            Repo.rollback("Invalid token")

          token ->
            case validate_installation_token_record(cleartext, token) do
              {:error, reason} ->
                Repo.rollback(reason)

              {:ok, token} ->
                token
                |> Ecto.Changeset.change(
                  use_count: token.use_count + 1,
                  last_used_at: DateTime.utc_now(),
                  consumed_at: DateTime.utc_now(),
                  consumed_agent_id: agent_id
                )
                |> Repo.update!()

                :ok
            end
        end
      end)
      |> case do
        {:ok, :ok} -> :ok
        {:error, reason} -> {:error, reason}
      end
    end)
  rescue
    e ->
      require Logger

      Logger.error(
        "Failed to finalize installation token for agent #{agent_id}: #{Exception.message(e)}"
      )

      {:error, :token_finalize_failed}
  end

  defp cleanup_failed_enrollment(agent_id) do
    with_enrollment_bypass(fn ->
      Repo.delete_all(from(t in AgentToken, where: t.agent_id == ^agent_id))
      Repo.delete_all(from(c in AgentCredential, where: c.agent_id == ^agent_id))
      Repo.delete_all(from(a in Agent, where: a.id == ^agent_id and a.status == "registered"))
    end)

    :ok
  rescue
    e ->
      require Logger

      Logger.warning(
        "Failed to cleanup incomplete enrollment for agent #{agent_id}: #{Exception.message(e)}"
      )

      :ok
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
      current_token_generation: 1,
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

    case Repo.insert_all("agents", [attrs],
           on_conflict: [
             set: [
               hostname: hostname,
               os_type: os_type,
               os_version: os_version,
               agent_version: agent_version,
               machine_id: machine_id,
               status: "registered",
               last_seen_at: now,
               token_rotation_enabled: true,
               token_ttl_hours: 720,
               token_refresh_window_percent: 60,
               updated_at: now,
               config: attrs.config
             ]
           ],
           conflict_target: [:id]
         ) do
      {_count, _rows} -> :ok
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

  defp generate_agent_jwt(agent_id, org_id) do
    # Use TokenManager for JWT generation with rotation support.
    try do
      case TamanduaServer.Agents.TokenManager.issue_token(agent_id) do
        {:ok, jwt, _token_record} ->
          {:ok, jwt}

        {:error, :token_rotation_disabled} ->
          maybe_legacy_agent_jwt(agent_id, org_id, :token_rotation_disabled)

        {:error, reason} ->
          maybe_legacy_agent_jwt(agent_id, org_id, reason)
      end
    catch
      :exit, reason ->
        maybe_legacy_agent_jwt(agent_id, org_id, {:exit, reason})
    end
  end

  defp maybe_legacy_agent_jwt(agent_id, org_id, reason) do
    env = Application.get_env(:tamandua_server, :env, :prod)

    if env in [:dev, :test] or System.get_env("TAMANDUA_LAB_LIGHT", "false") == "true" do
      {:ok, legacy_agent_jwt(agent_id, org_id)}
    else
      require Logger
      Logger.error("Refusing legacy agent token fallback in production: #{inspect(reason)}")
      {:error, reason}
    end
  end

  defp legacy_agent_jwt(agent_id, org_id) do
    claims = %{
      agent_id: agent_id,
      org_id: org_id,
      organization_id: org_id,
      type: "agent",
      iat: DateTime.utc_now() |> DateTime.to_unix()
    }

    Phoenix.Token.sign(
      TamanduaServerWeb.Endpoint,
      "agent_auth",
      claims,
      max_age: 720 * 3600
    )
  end

  defp openssl(args) do
    OSCommand.run("openssl", args)
  end
end
