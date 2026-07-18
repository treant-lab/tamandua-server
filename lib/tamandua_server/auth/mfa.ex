defmodule TamanduaServer.Auth.MFA do
  @moduledoc """
  Multi-Factor Authentication orchestrator.
  Manages MFA enrollment, verification, backup codes, and trusted devices.
  """

  import Ecto.Query
  alias TamanduaServer.Repo
  alias TamanduaServer.Auth.MFA.{Credential, BackupCode, TrustedDevice, Policy, TOTP, SMS, Email, WebAuthn}

  require Logger

  # ============================================================================
  # Enrollment
  # ============================================================================

  @doc """
  Start TOTP enrollment for a user.
  Returns the secret and provisioning URI for QR code generation.
  """
  def start_totp_enrollment(user, opts \\ []) do
    secret = TOTP.generate_secret()
    name = Keyword.get(opts, :name, "Authenticator App")
    created_ip = Keyword.get(opts, :ip_address)

    attrs = %{
      user_id: user.id,
      type: "totp",
      name: name,
      totp_secret: secret,
      is_verified: false,
      created_ip: created_ip
    }

    case Repo.insert(Credential.changeset(%Credential{}, attrs)) do
      {:ok, credential} ->
        provisioning_uri = TOTP.provisioning_uri(secret, user.email)
        {:ok, credential, %{secret: secret, provisioning_uri: provisioning_uri}}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Complete TOTP enrollment by verifying the code.
  """
  def complete_totp_enrollment(credential_id, code) do
    credential = Repo.get(Credential, credential_id)

    if credential && credential.type == "totp" do
      if TOTP.verify(credential.totp_secret, code) do
        credential
        |> Ecto.Changeset.change(is_verified: true)
        |> maybe_set_as_primary()
        |> Repo.update()
      else
        {:error, :invalid_code}
      end
    else
      {:error, :credential_not_found}
    end
  end

  @doc """
  Start SMS enrollment for a user.
  """
  def start_sms_enrollment(user, phone_number, opts \\ []) do
    name = Keyword.get(opts, :name, "SMS")
    created_ip = Keyword.get(opts, :ip_address)

    with {:ok, code} <- SMS.send_code(phone_number) do
      attrs = %{
        user_id: user.id,
        type: "sms",
        name: name,
        phone_number: phone_number,
        last_code: SMS.hash_code(code),
        last_code_sent_at: DateTime.utc_now(),
        is_verified: false,
        created_ip: created_ip
      }

      case Repo.insert(Credential.changeset(%Credential{}, attrs)) do
        {:ok, credential} ->
          {:ok, credential}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Complete SMS enrollment by verifying the code.
  """
  def complete_sms_enrollment(credential_id, code) do
    credential = Repo.get(Credential, credential_id)

    if credential && credential.type == "sms" do
      if SMS.verify(credential.last_code, credential.last_code_sent_at, code) do
        credential
        |> Ecto.Changeset.change(is_verified: true)
        |> maybe_set_as_primary()
        |> Repo.update()
      else
        {:error, :invalid_code}
      end
    else
      {:error, :credential_not_found}
    end
  end

  @doc """
  Start email enrollment for a user.
  """
  def start_email_enrollment(user, email_address, opts \\ []) do
    name = Keyword.get(opts, :name, "Email")
    created_ip = Keyword.get(opts, :ip_address)

    with {:ok, code} <- Email.send_code(email_address) do
      attrs = %{
        user_id: user.id,
        type: "email",
        name: name,
        email: email_address,
        last_code: Email.hash_code(code),
        last_code_sent_at: DateTime.utc_now(),
        is_verified: false,
        created_ip: created_ip
      }

      case Repo.insert(Credential.changeset(%Credential{}, attrs)) do
        {:ok, credential} ->
          {:ok, credential}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  @doc """
  Complete email enrollment by verifying the code.
  """
  def complete_email_enrollment(credential_id, code) do
    credential = Repo.get(Credential, credential_id)

    if credential && credential.type == "email" do
      if Email.verify(credential.last_code, credential.last_code_sent_at, code) do
        credential
        |> Ecto.Changeset.change(is_verified: true)
        |> maybe_set_as_primary()
        |> Repo.update()
      else
        {:error, :invalid_code}
      end
    else
      {:error, :credential_not_found}
    end
  end

  @doc """
  Start WebAuthn enrollment.
  Returns challenge and options for the client.
  """
  def start_webauthn_enrollment(user, opts \\ []) do
    created_ip = Keyword.get(opts, :ip_address)

    case WebAuthn.generate_registration_challenge(user) do
      {:ok, challenge, options} ->
        # Store challenge temporarily (you may want to use a GenServer or ETS)
        # For now, we'll return it and trust the client to send it back
        {:ok, challenge, options, created_ip}

      error ->
        error
    end
  end

  @doc """
  Complete WebAuthn enrollment.
  """
  def complete_webauthn_enrollment(user, challenge, response, opts \\ []) do
    name = Keyword.get(opts, :name, "Security Key")
    created_ip = Keyword.get(opts, :ip_address)

    with {:ok, auth_data} <- WebAuthn.verify_registration(challenge, response) do
      attrs = %{
        user_id: user.id,
        type: "webauthn",
        name: name,
        credential_id: auth_data.credential_id,
        public_key: auth_data.public_key,
        counter: auth_data.counter,
        aaguid: auth_data.aaguid,
        transports: response["transports"] || [],
        is_verified: true,  # WebAuthn is verified immediately
        created_ip: created_ip
      }

      %Credential{}
      |> Credential.changeset(attrs)
      |> maybe_set_as_primary()
      |> Repo.insert()
    end
  end

  # ============================================================================
  # Authentication
  # ============================================================================

  @doc """
  Verify MFA code for a user.
  Returns {:ok, credential} on success.
  """
  def verify_mfa(user, code, opts \\ []) do
    credentials = list_verified_credentials(user.id)

    # Try each credential until one works
    result =
      Enum.find_value(credentials, fn credential ->
        case verify_credential(credential, code) do
          true ->
            # Update last used timestamp
            credential
            |> Credential.touch_last_used()
            |> Repo.update()

            {:ok, credential}

          false ->
            nil
        end
      end)

    case result do
      {:ok, credential} ->
        # Check if we should create a trusted device
        if Keyword.get(opts, :remember_device, false) do
          create_trusted_device(user, opts)
        end

        {:ok, credential}

      nil ->
        # Try backup codes
        verify_backup_code(user, code, opts)
    end
  end

  @doc """
  Send a new MFA code (for SMS/Email).
  """
  def send_mfa_code(credential_id) do
    credential = Repo.get(Credential, credential_id)

    case credential do
      %Credential{type: "sms", phone_number: phone} when not is_nil(phone) ->
        with {:ok, code} <- SMS.send_code(phone) do
          credential
          |> Ecto.Changeset.change(
            last_code: SMS.hash_code(code),
            last_code_sent_at: DateTime.utc_now()
          )
          |> Repo.update()
        end

      %Credential{type: "email", email: email} when not is_nil(email) ->
        with {:ok, code} <- Email.send_code(email) do
          credential
          |> Ecto.Changeset.change(
            last_code: Email.hash_code(code),
            last_code_sent_at: DateTime.utc_now()
          )
          |> Repo.update()
        end

      _ ->
        {:error, :invalid_credential_type}
    end
  end

  # ============================================================================
  # Backup Codes
  # ============================================================================

  @doc """
  Generate backup codes for a user (10 codes).
  Returns {:ok, codes} where codes is a list of plain-text codes to show to the user.
  """
  def generate_backup_codes(user) do
    # Delete existing backup codes
    from(bc in BackupCode, where: bc.user_id == ^user.id)
    |> Repo.delete_all()

    # Generate 10 new codes
    codes =
      for _ <- 1..10 do
        code = BackupCode.generate_code()

        %BackupCode{}
        |> BackupCode.changeset(%{
          user_id: user.id,
          code_hash: BackupCode.hash_code(code)
        })
        |> Repo.insert!()

        code
      end

    {:ok, codes}
  end

  @doc """
  Verify a backup code.
  """
  def verify_backup_code(user, code, opts \\ []) do
    backup_codes =
      from(bc in BackupCode,
        where: bc.user_id == ^user.id and is_nil(bc.used_at)
      )
      |> Repo.all()

    result =
      Enum.find_value(backup_codes, fn backup_code ->
        if BackupCode.verify_code(code, backup_code.code_hash) do
          # Mark as used
          ip_address = Keyword.get(opts, :ip_address)

          backup_code
          |> BackupCode.mark_used(ip_address)
          |> Repo.update()

          {:ok, :backup_code}
        else
          nil
        end
      end)

    result || {:error, :invalid_code}
  end

  @doc """
  Count remaining backup codes for a user.
  """
  def count_backup_codes(user_id) do
    from(bc in BackupCode,
      where: bc.user_id == ^user_id and is_nil(bc.used_at),
      select: count()
    )
    |> Repo.one()
  end

  # ============================================================================
  # Trusted Devices
  # ============================================================================

  @doc """
  Create a trusted device for a user.
  Returns {:ok, token} where token should be stored in a cookie.
  """
  def create_trusted_device(user, opts \\ []) do
    token = TrustedDevice.generate_token()
    ip_address = Keyword.get(opts, :ip_address)
    user_agent = Keyword.get(opts, :user_agent)
    name = Keyword.get(opts, :device_name, generate_device_name(user_agent))
    fingerprint = TrustedDevice.generate_fingerprint(user_agent || "", ip_address || "")

    attrs = %{
      user_id: user.id,
      token_hash: TrustedDevice.hash_token(token),
      name: name,
      fingerprint: fingerprint,
      ip_address: ip_address,
      user_agent: user_agent
    }

    case Repo.insert(TrustedDevice.changeset(%TrustedDevice{}, attrs)) do
      {:ok, _device} ->
        {:ok, token}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Verify a trusted device token.
  """
  def verify_trusted_device(user_id, token) do
    devices =
      from(td in TrustedDevice,
        where: td.user_id == ^user_id and is_nil(td.revoked_at)
      )
      |> Repo.all()

    result =
      Enum.find_value(devices, fn device ->
        if TrustedDevice.verify_token(token, device.token_hash) && TrustedDevice.valid?(device) do
          # Update last used
          device
          |> TrustedDevice.touch_last_used()
          |> Repo.update()

          {:ok, device}
        else
          nil
        end
      end)

    result || {:error, :invalid_token}
  end

  @doc """
  List trusted devices for a user.
  """
  def list_trusted_devices(user_id) do
    from(td in TrustedDevice,
      where: td.user_id == ^user_id and is_nil(td.revoked_at),
      order_by: [desc: td.last_used_at]
    )
    |> Repo.all()
  end

  @doc """
  Revoke a trusted device.
  """
  def revoke_trusted_device(device_id) do
    case Repo.get(TrustedDevice, device_id) do
      nil ->
        {:error, :not_found}

      device ->
        device
        |> TrustedDevice.revoke()
        |> Repo.update()
    end
  end

  @doc """
  Revoke all trusted devices for a user.
  """
  def revoke_all_trusted_devices(user_id) do
    from(td in TrustedDevice,
      where: td.user_id == ^user_id and is_nil(td.revoked_at)
    )
    |> Repo.update_all(set: [revoked_at: DateTime.utc_now()])
  end

  # ============================================================================
  # Credentials Management
  # ============================================================================

  @doc """
  List all credentials for a user.
  """
  def list_credentials(user_id) do
    from(c in Credential,
      where: c.user_id == ^user_id,
      order_by: [desc: c.is_primary, desc: c.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  List verified credentials for a user.
  """
  def list_verified_credentials(user_id) do
    from(c in Credential,
      where: c.user_id == ^user_id and c.is_verified == true,
      order_by: [desc: c.is_primary, desc: c.inserted_at]
    )
    |> Repo.all()
  end

  @doc """
  Get a credential by ID.
  """
  def get_credential(credential_id) do
    Repo.get(Credential, credential_id)
  end

  @doc """
  Delete a credential.
  """
  def delete_credential(credential_id) do
    case Repo.get(Credential, credential_id) do
      nil ->
        {:error, :not_found}

      credential ->
        # If this was the primary credential, promote another
        if credential.is_primary do
          promote_next_primary(credential.user_id, credential_id)
        end

        Repo.delete(credential)
    end
  end

  @doc """
  Set a credential as primary.
  """
  def set_primary_credential(credential_id) do
    credential = Repo.get(Credential, credential_id)

    if credential do
      # Unset current primary
      from(c in Credential,
        where: c.user_id == ^credential.user_id and c.is_primary == true
      )
      |> Repo.update_all(set: [is_primary: false])

      # Set new primary
      credential
      |> Ecto.Changeset.change(is_primary: true)
      |> Repo.update()
    else
      {:error, :not_found}
    end
  end

  # ============================================================================
  # Policy Management
  # ============================================================================

  @doc """
  Get or create MFA policy for an organization.
  """
  def get_or_create_policy(organization_id) do
    case Repo.get_by(Policy, organization_id: organization_id) do
      nil ->
        %Policy{}
        |> Policy.changeset(%{organization_id: organization_id})
        |> Repo.insert()

      policy ->
        {:ok, policy}
    end
  end

  @doc """
  Update MFA policy for an organization.
  """
  def update_policy(organization_id, attrs) do
    case get_or_create_policy(organization_id) do
      {:ok, policy} ->
        policy
        |> Policy.changeset(attrs)
        |> Repo.update()

      error ->
        error
    end
  end

  @doc """
  Check if MFA is required for a user.
  """
  def mfa_required?(user) do
    case Repo.get_by(Policy, organization_id: user.organization_id) do
      nil ->
        false

      policy ->
        Policy.mfa_required?(policy, user)
    end
  end

  @doc """
  Check if user is in MFA grace period.
  """
  def in_grace_period?(user) do
    if user.mfa_grace_expires_at do
      DateTime.compare(DateTime.utc_now(), user.mfa_grace_expires_at) == :lt
    else
      false
    end
  end

  @doc """
  Check if IP address bypasses MFA (trusted IP).
  """
  def ip_bypasses_mfa?(user, ip_address) do
    case Repo.get_by(Policy, organization_id: user.organization_id) do
      nil ->
        false

      policy ->
        Policy.ip_trusted?(policy, ip_address)
    end
  end

  # ============================================================================
  # Private Helpers
  # ============================================================================

  defp verify_credential(%Credential{type: "totp", totp_secret: secret}, code) do
    TOTP.verify(secret, code)
  end

  defp verify_credential(%Credential{type: "sms", last_code: last_code, last_code_sent_at: sent_at}, code) do
    SMS.verify(last_code, sent_at, code)
  end

  defp verify_credential(%Credential{type: "email", last_code: last_code, last_code_sent_at: sent_at}, code) do
    Email.verify(last_code, sent_at, code)
  end

  defp verify_credential(%Credential{type: "webauthn"}, _code) do
    # WebAuthn uses a different flow
    false
  end

  defp verify_credential(_, _), do: false

  defp maybe_set_as_primary(changeset) do
    user_id = Ecto.Changeset.get_field(changeset, :user_id)

    # Check if this is the first credential
    existing_count =
      from(c in Credential, where: c.user_id == ^user_id, select: count())
      |> Repo.one()

    if existing_count == 0 do
      Ecto.Changeset.put_change(changeset, :is_primary, true)
    else
      changeset
    end
  end

  defp promote_next_primary(user_id, excluding_id) do
    next_credential =
      from(c in Credential,
        where: c.user_id == ^user_id and c.id != ^excluding_id and c.is_verified == true,
        order_by: [desc: c.inserted_at],
        limit: 1
      )
      |> Repo.one()

    if next_credential do
      next_credential
      |> Ecto.Changeset.change(is_primary: true)
      |> Repo.update()
    end
  end

  defp generate_device_name(nil), do: "Unknown Device"

  defp generate_device_name(user_agent) do
    cond do
      String.contains?(user_agent, "Chrome") -> "Chrome Browser"
      String.contains?(user_agent, "Firefox") -> "Firefox Browser"
      String.contains?(user_agent, "Safari") -> "Safari Browser"
      String.contains?(user_agent, "Edge") -> "Edge Browser"
      true -> "Web Browser"
    end
  end
end
