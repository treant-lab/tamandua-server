defmodule TamanduaServer.Auth.MFATest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Auth.MFA
  alias TamanduaServer.Auth.MFA.{Credential, BackupCode, TrustedDevice, Policy, TOTP}
  alias TamanduaServer.Accounts

  describe "TOTP enrollment" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      %{user: user, org: org}
    end

    test "start_totp_enrollment/2 generates secret and provisioning URI", %{user: user} do
      assert {:ok, credential, %{secret: secret, provisioning_uri: uri}} =
               MFA.start_totp_enrollment(user)

      assert credential.type == "totp"
      assert credential.user_id == user.id
      assert credential.is_verified == false
      assert String.length(secret) > 0
      assert String.contains?(uri, "otpauth://totp/")
      assert String.contains?(uri, user.email)
    end

    test "complete_totp_enrollment/2 verifies code and marks as verified", %{user: user} do
      {:ok, credential, %{secret: secret}} = MFA.start_totp_enrollment(user)

      # Generate valid TOTP code
      code = TOTP.generate_current(secret)

      assert {:ok, verified_credential} = MFA.complete_totp_enrollment(credential.id, code)
      assert verified_credential.is_verified == true
      assert verified_credential.is_primary == true  # First credential becomes primary
    end

    test "complete_totp_enrollment/2 rejects invalid code", %{user: user} do
      {:ok, credential, _} = MFA.start_totp_enrollment(user)

      assert {:error, :invalid_code} = MFA.complete_totp_enrollment(credential.id, "000000")
    end
  end

  describe "SMS enrollment" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      # Enable mock SMS for testing
      Application.put_env(:tamandua_server, :mock_sms, true)

      on_exit(fn ->
        Application.delete_env(:tamandua_server, :mock_sms)
      end)

      %{user: user, org: org}
    end

    test "start_sms_enrollment/3 sends SMS and creates credential", %{user: user} do
      phone = "+15551234567"

      assert {:ok, credential} = MFA.start_sms_enrollment(user, phone)
      assert credential.type == "sms"
      assert credential.phone_number == phone
      assert credential.is_verified == false
      assert credential.last_code != nil
      assert credential.last_code_sent_at != nil
    end

    test "SMS rate limiting works", %{user: user} do
      phone = "+15551234567"

      # First 3 should succeed
      assert {:ok, _} = MFA.start_sms_enrollment(user, phone)
      assert {:ok, _} = MFA.start_sms_enrollment(user, phone)
      assert {:ok, _} = MFA.start_sms_enrollment(user, phone)

      # 4th should be rate limited
      assert {:error, :rate_limited} = MFA.start_sms_enrollment(user, phone)
    end
  end

  describe "backup codes" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      %{user: user}
    end

    test "generate_backup_codes/1 creates 10 codes", %{user: user} do
      assert {:ok, codes} = MFA.generate_backup_codes(user)
      assert length(codes) == 10
      assert Enum.all?(codes, fn code -> String.length(code) == 8 end)
    end

    test "verify_backup_code/3 works and marks code as used", %{user: user} do
      {:ok, codes} = MFA.generate_backup_codes(user)
      code = List.first(codes)

      assert {:ok, :backup_code} = MFA.verify_backup_code(user, code, ip_address: "127.0.0.1")

      # Code should be marked as used and not work again
      assert {:error, :invalid_code} = MFA.verify_backup_code(user, code, ip_address: "127.0.0.1")
    end

    test "count_backup_codes/1 returns correct count", %{user: user} do
      assert MFA.count_backup_codes(user.id) == 0

      {:ok, codes} = MFA.generate_backup_codes(user)
      assert MFA.count_backup_codes(user.id) == 10

      # Use one code
      code = List.first(codes)
      MFA.verify_backup_code(user, code, ip_address: "127.0.0.1")
      assert MFA.count_backup_codes(user.id) == 9
    end

    test "generate_backup_codes/1 replaces existing codes", %{user: user} do
      {:ok, codes1} = MFA.generate_backup_codes(user)
      {:ok, codes2} = MFA.generate_backup_codes(user)

      # Old codes should not work
      assert {:error, :invalid_code} =
               MFA.verify_backup_code(user, List.first(codes1), ip_address: "127.0.0.1")

      # New codes should work
      assert {:ok, :backup_code} =
               MFA.verify_backup_code(user, List.first(codes2), ip_address: "127.0.0.1")
    end
  end

  describe "trusted devices" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      %{user: user}
    end

    test "create_trusted_device/2 creates device with token", %{user: user} do
      opts = [
        ip_address: "192.168.1.1",
        user_agent: "Mozilla/5.0 Chrome/100.0"
      ]

      assert {:ok, token} = MFA.create_trusted_device(user, opts)
      assert is_binary(token)
    end

    test "verify_trusted_device/2 verifies valid token", %{user: user} do
      opts = [ip_address: "192.168.1.1", user_agent: "Chrome"]
      {:ok, token} = MFA.create_trusted_device(user, opts)

      assert {:ok, device} = MFA.verify_trusted_device(user.id, token)
      assert device.user_id == user.id
    end

    test "verify_trusted_device/2 rejects invalid token", %{user: user} do
      assert {:error, :invalid_token} = MFA.verify_trusted_device(user.id, "invalid-token")
    end

    test "revoke_trusted_device/1 revokes device", %{user: user} do
      {:ok, token} = MFA.create_trusted_device(user, [])
      {:ok, device} = MFA.verify_trusted_device(user.id, token)

      assert {:ok, _} = MFA.revoke_trusted_device(device.id)
      assert {:error, :invalid_token} = MFA.verify_trusted_device(user.id, token)
    end

    test "revoke_all_trusted_devices/1 revokes all devices", %{user: user} do
      {:ok, token1} = MFA.create_trusted_device(user, [])
      {:ok, token2} = MFA.create_trusted_device(user, [])

      assert {2, _} = MFA.revoke_all_trusted_devices(user.id)

      assert {:error, :invalid_token} = MFA.verify_trusted_device(user.id, token1)
      assert {:error, :invalid_token} = MFA.verify_trusted_device(user.id, token2)
    end
  end

  describe "MFA verification" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      # Set up TOTP credential
      {:ok, credential, %{secret: secret}} = MFA.start_totp_enrollment(user)
      code = TOTP.generate_current(secret)
      {:ok, credential} = MFA.complete_totp_enrollment(credential.id, code)

      %{user: user, credential: credential, secret: secret}
    end

    test "verify_mfa/3 accepts valid TOTP code", %{user: user, secret: secret} do
      code = TOTP.generate_current(secret)
      assert {:ok, _credential} = MFA.verify_mfa(user, code)
    end

    test "verify_mfa/3 rejects invalid code", %{user: user} do
      assert {:error, :invalid_code} = MFA.verify_mfa(user, "000000")
    end

    test "verify_mfa/3 creates trusted device when requested", %{user: user, secret: secret} do
      code = TOTP.generate_current(secret)

      opts = [
        remember_device: true,
        ip_address: "192.168.1.1",
        user_agent: "Chrome"
      ]

      assert {:ok, _credential} = MFA.verify_mfa(user, code, opts)
      assert length(MFA.list_trusted_devices(user.id)) == 1
    end

    test "verify_mfa/3 falls back to backup codes", %{user: user} do
      {:ok, codes} = MFA.generate_backup_codes(user)
      code = List.first(codes)

      assert {:ok, :backup_code} = MFA.verify_mfa(user, code)
    end
  end

  describe "MFA policies" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "admin@example.com",
          password: "password123",
          role: "admin",
          organization_id: org.id
        })

      %{user: user, org: org}
    end

    test "get_or_create_policy/1 creates default policy", %{org: org} do
      assert {:ok, policy} = MFA.get_or_create_policy(org.id)
      assert policy.enforcement_mode == "optional"
      assert policy.grace_period_days == 7
    end

    test "update_policy/2 updates policy", %{org: org} do
      {:ok, _policy} = MFA.get_or_create_policy(org.id)

      assert {:ok, updated} =
               MFA.update_policy(org.id, %{
                 enforcement_mode: "required_all",
                 grace_period_days: 14
               })

      assert updated.enforcement_mode == "required_all"
      assert updated.grace_period_days == 14
    end

    test "mfa_required?/1 enforces required_all policy", %{user: user, org: org} do
      MFA.update_policy(org.id, %{enforcement_mode: "required_all"})
      user = %{user | organization_id: org.id}

      assert MFA.mfa_required?(user) == true
    end

    test "mfa_required?/1 enforces required_admins policy", %{user: user, org: org} do
      MFA.update_policy(org.id, %{enforcement_mode: "required_admins"})
      user = %{user | organization_id: org.id, role: "admin"}

      assert MFA.mfa_required?(user) == true

      user_analyst = %{user | role: "analyst"}
      assert MFA.mfa_required?(user_analyst) == false
    end

    test "ip_bypasses_mfa?/2 checks trusted IP ranges", %{user: user, org: org} do
      MFA.update_policy(org.id, %{trusted_ip_ranges: ["192.168.1.0/24", "10.0.0.0/8"]})
      user = %{user | organization_id: org.id}

      assert MFA.ip_bypasses_mfa?(user, "192.168.1.100") == true
      assert MFA.ip_bypasses_mfa?(user, "10.5.6.7") == true
      assert MFA.ip_bypasses_mfa?(user, "8.8.8.8") == false
    end
  end

  describe "credentials management" do
    setup do
      {:ok, org} = Accounts.create_organization(%{name: "Test Org", slug: "test-org"})

      {:ok, user} =
        Accounts.create_user(%{
          email: "test@example.com",
          password: "password123",
          organization_id: org.id
        })

      %{user: user}
    end

    test "list_credentials/1 returns user credentials", %{user: user} do
      assert [] = MFA.list_credentials(user.id)

      {:ok, _credential, _} = MFA.start_totp_enrollment(user)
      credentials = MFA.list_credentials(user.id)

      assert length(credentials) == 1
    end

    test "list_verified_credentials/1 returns only verified credentials", %{user: user} do
      {:ok, credential, %{secret: secret}} = MFA.start_totp_enrollment(user)

      assert [] = MFA.list_verified_credentials(user.id)

      code = TOTP.generate_current(secret)
      {:ok, _} = MFA.complete_totp_enrollment(credential.id, code)

      verified = MFA.list_verified_credentials(user.id)
      assert length(verified) == 1
    end

    test "set_primary_credential/1 sets credential as primary", %{user: user} do
      {:ok, cred1, %{secret: secret1}} = MFA.start_totp_enrollment(user)
      code1 = TOTP.generate_current(secret1)
      {:ok, _} = MFA.complete_totp_enrollment(cred1.id, code1)

      {:ok, cred2, %{secret: secret2}} = MFA.start_totp_enrollment(user)
      code2 = TOTP.generate_current(secret2)
      {:ok, _} = MFA.complete_totp_enrollment(cred2.id, code2)

      assert {:ok, updated} = MFA.set_primary_credential(cred2.id)
      assert updated.is_primary == true

      # First credential should no longer be primary
      cred1_reloaded = MFA.get_credential(cred1.id)
      assert cred1_reloaded.is_primary == false
    end

    test "delete_credential/1 promotes next credential if deleting primary", %{user: user} do
      {:ok, cred1, %{secret: secret1}} = MFA.start_totp_enrollment(user)
      code1 = TOTP.generate_current(secret1)
      {:ok, cred1} = MFA.complete_totp_enrollment(cred1.id, code1)

      {:ok, cred2, %{secret: secret2}} = MFA.start_totp_enrollment(user)
      code2 = TOTP.generate_current(secret2)
      {:ok, cred2} = MFA.complete_totp_enrollment(cred2.id, code2)

      # cred1 is primary (first credential)
      assert cred1.is_primary == true

      # Delete primary
      assert {:ok, _} = MFA.delete_credential(cred1.id)

      # cred2 should now be primary
      cred2_reloaded = MFA.get_credential(cred2.id)
      assert cred2_reloaded.is_primary == true
    end
  end
end
