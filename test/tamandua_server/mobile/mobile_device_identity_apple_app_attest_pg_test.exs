defmodule TamanduaServer.Mobile.MobileDeviceIdentityAppleAppAttestPgTest do
  use TamanduaServer.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias TamanduaServer.AppleAppAttestFixture

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityAppleAppAttest,
    MobileDeviceIdentityAppleContext,
    MobileDeviceIdentityAppleFlow,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityProviderKey
  }

  @now ~U[2026-07-16 16:00:00.000000Z]

  test "appAttestProof.js-shaped two-phase envelopes activate only after first assertion" do
    organization = insert(:organization)
    key = app_key()
    root = AppleAppAttestFixture.root()

    {issued, attestation_params, profile} =
      stage_attestation(organization.id, "ios-staged-ok", key, root)

    with_apple_config(profile, fn ->
      assert {:ok, attestation_receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 attestation_params,
                 now: @now
               )

      refute Repo.exists?(MobileDeviceIdentityKey)
      refute Repo.exists?(MobileDeviceIdentityProviderKey)

      assertion_params = assertion_params(attestation_receipt, key, root)

      assert {:ok, assertion_receipt} =
               MobileDeviceIdentityAppleFlow.submit_assertion(
                 organization.id,
                 assertion_params,
                 now: @now
               )

      identity = Repo.one!(MobileDeviceIdentityKey)
      provider = Repo.one!(MobileDeviceIdentityProviderKey)
      context = Repo.get!(MobileDeviceIdentityAppleContext, issued.challenge_id)

      assert assertion_receipt.phase == "assert"
      assert assertion_receipt.parent_attestation_receipt_id == attestation_receipt.receipt_id
      assert identity.public_key_spki == AppleAppAttestFixture.public_key_spki(key)
      assert identity.attestation_state == "verified_app_attest"
      assert provider.public_key_spki == identity.public_key_spki
      assert provider.sign_count == 1
      assert context.state == "consumed"
      assert context.consumed_at == @now

      assert {:error, :app_attest_context_unavailable} =
               MobileDeviceIdentityAppleFlow.submit_assertion(
                 organization.id,
                 assertion_params,
                 now: @now
               )
    end)
  end

  test "expired attestation and swapped parent receipts remain pending without identities" do
    organization = insert(:organization)
    root = AppleAppAttestFixture.root()
    first_key = app_key()
    second_key = app_key()

    {first, first_params, profile} =
      stage_attestation(organization.id, "ios-mixup-a", first_key, root)

    {second, second_params, _profile} =
      stage_attestation(organization.id, "ios-mixup-b", second_key, root)

    with_apple_config(profile, fn ->
      assert {:error, :app_attest_context_expired} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 first_params,
                 now: DateTime.add(@now, 301, :second)
               )

      assert Repo.get!(MobileDeviceIdentityAppleContext, first.challenge_id).state ==
               "attest_pending"

      assert {:ok, first_receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 first_params,
                 now: @now
               )

      assert {:ok, second_receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 second_params,
                 now: @now
               )

      swapped =
        second_receipt
        |> assertion_params(second_key, root)
        |> Map.put(:parent_attestation_receipt_id, first_receipt.receipt_id)

      assert {:error, :app_attest_binding_mismatch} =
               MobileDeviceIdentityAppleFlow.submit_assertion(
                 organization.id,
                 swapped,
                 now: @now
               )

      assert Repo.get!(MobileDeviceIdentityAppleContext, second.challenge_id).state ==
               "assert_pending"

      refute Repo.exists?(MobileDeviceIdentityKey)
      refute Repo.exists?(MobileDeviceIdentityProviderKey)
    end)
  end

  test "two staged contexts racing one opaque credential produce one atomic winner" do
    organization = insert(:organization)
    key = app_key()
    root = AppleAppAttestFixture.root()

    {_first, first_params, profile} =
      stage_attestation(organization.id, "ios-stage-race-a", key, root)

    {_second, second_params, _profile} =
      stage_attestation(organization.id, "ios-stage-race-b", key, root)

    with_apple_config(profile, fn ->
      assert {:ok, first_receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 first_params,
                 now: @now
               )

      assert {:ok, second_receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 second_params,
                 now: @now
               )

      proofs = [
        assertion_params(first_receipt, key, root),
        assertion_params(second_receipt, key, root)
      ]

      parent = self()

      tasks =
        for proof <- proofs do
          Task.async(fn ->
            send(parent, {:apple_staged_racer_ready, self()})

            receive do
              :go ->
                MobileDeviceIdentityAppleFlow.submit_assertion(organization.id, proof, now: @now)
            end
          end)
        end

      for task <- tasks do
        task_pid = task.pid
        assert_receive {:apple_staged_racer_ready, ^task_pid}
        Sandbox.allow(Repo, self(), task.pid)
      end

      Enum.each(tasks, &send(&1.pid, :go))
      results = Enum.map(tasks, &Task.await(&1, 5_000))

      assert Enum.count(results, &match?({:ok, _}, &1)) == 1
      assert Enum.count(results, &(&1 == {:error, :device_identity_conflict})) == 1
      assert Repo.aggregate(MobileDeviceIdentityKey, :count) == 1
      assert Repo.aggregate(MobileDeviceIdentityProviderKey, :count) == 1

      assert Repo.aggregate(
               from(c in MobileDeviceIdentityAppleContext, where: c.state == "consumed"),
               :count
             ) == 1

      assert Repo.aggregate(
               from(c in MobileDeviceIdentityChallenge, where: c.state == "consumed"),
               :count
             ) == 1
    end)
  end

  test "profile tuple reconfiguration between phases fails closed and preserves pending state" do
    organization = insert(:organization)
    key = app_key()
    root = AppleAppAttestFixture.root()

    {issued, attestation_params, profile} =
      stage_attestation(organization.id, "ios-profile-toctou", key, root)

    with_apple_config(profile, fn ->
      assert {:ok, receipt} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 attestation_params,
                 now: @now
               )

      assertion = assertion_params(receipt, key, root)
      [profile_id] = Map.keys(profile)
      reconfigured = put_in(profile, [profile_id, "environment"], "production")

      with_apple_config(reconfigured, fn ->
        assert {:error, :apple_app_attest_binding_invalid} =
                 MobileDeviceIdentityAppleFlow.submit_assertion(
                   organization.id,
                   assertion,
                   now: @now
                 )
      end)

      context = Repo.get!(MobileDeviceIdentityAppleContext, issued.challenge_id)

      challenge =
        Repo.get!(MobileDeviceIdentityChallenge, receipt.assertion_challenge.challenge_id)

      assert context.state == "assert_pending"
      assert context.environment == "development"
      assert challenge.state == "pending"
      refute Repo.exists?(MobileDeviceIdentityKey)
      refute Repo.exists?(MobileDeviceIdentityProviderKey)
    end)
  end

  test "oversized encoded client data is rejected before staged verification and rolls back" do
    organization = insert(:organization)
    key = app_key()
    root = AppleAppAttestFixture.root()

    {issued, attestation_params, profile} =
      stage_attestation(organization.id, "ios-oversized-client-data", key, root)

    oversized =
      put_in(
        attestation_params,
        [:client_data, :payload_base64url],
        String.duplicate("A", 10_925)
      )

    with_apple_config(profile, fn ->
      assert {:error, :app_attest_client_data_mismatch} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 oversized,
                 now: @now
               )

      oversized_key =
        Map.put(attestation_params, :key_id_base64url, String.duplicate("A", 1_024))

      assert {:error, :invalid_app_attest_request} =
               MobileDeviceIdentityAppleFlow.submit_attestation(
                 organization.id,
                 oversized_key,
                 now: @now
               )

      assert Repo.get!(MobileDeviceIdentityAppleContext, issued.challenge_id).state ==
               "attest_pending"

      refute Repo.exists?(MobileDeviceIdentityKey)
      refute Repo.exists?(MobileDeviceIdentityProviderKey)
    end)
  end

  defp stage_attestation(organization_id, installation_id, key, root) do
    request = %{
      protocol: "tamandua.mobile.app-attest/v1",
      provider: "apple_app_attest",
      organization_id: organization_id,
      installation_id: installation_id,
      platform: "ios",
      purpose: "bind"
    }

    # Bootstrap only discovers the governed profile; the actual staged challenge
    # is issued under that same profile after config is installed below.
    template =
      AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), "template", key: key, root: root)

    issued =
      with_apple_config(template.profile, fn ->
        assert {:ok, challenge} =
                 MobileDeviceIdentityAppleFlow.issue_challenge(organization_id, request,
                   now: @now
                 )

        challenge
      end)

    payload = Base.url_decode64!(issued.client_data.payload_base64url, padding: false)
    fixture = AppleAppAttestFixture.build(payload, "unused-first-assertion", key: key, root: root)

    params = %{
      protocol: issued.protocol,
      provider: issued.provider,
      challenge_id: issued.challenge_id,
      organization_id: issued.organization_id,
      installation_id: issued.installation_id,
      profile: issued.profile,
      platform: "ios",
      purpose: "bind",
      client_data: issued.client_data,
      key_id_base64url: fixture.evidence["key_id_base64url"],
      attestation_object_base64url: fixture.evidence["attestation_object_base64url"]
    }

    {issued, params, fixture.profile}
  end

  defp assertion_params(receipt, key, root) do
    challenge = receipt.assertion_challenge
    payload = Base.url_decode64!(challenge.client_data.payload_base64url, padding: false)

    fixture =
      AppleAppAttestFixture.build(:crypto.strong_rand_bytes(32), payload, key: key, root: root)

    %{
      protocol: challenge.protocol,
      provider: challenge.provider,
      challenge_id: challenge.challenge_id,
      organization_id: challenge.organization_id,
      installation_id: challenge.installation_id,
      profile: challenge.profile,
      client_data: challenge.client_data,
      key_id_base64url: fixture.evidence["key_id_base64url"],
      parent_attestation_receipt_id: receipt.receipt_id,
      parent_attestation_challenge_id: receipt.challenge_id,
      assertion_base64url: fixture.evidence["assertion_base64url"]
    }
  end

  defp app_key, do: :public_key.generate_key({:namedCurve, :secp256r1})

  defp with_apple_config(profile, callback) do
    previous = Application.get_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest, :missing)
    [profile_id] = Map.keys(profile)

    Application.put_env(
      :tamandua_server,
      MobileDeviceIdentityAppleAppAttest,
      app_profiles: profile,
      default_profile_id: profile_id,
      unverified_evidence_policy: :reject
    )

    try do
      callback.()
    after
      case previous do
        :missing -> Application.delete_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest)
        value -> Application.put_env(:tamandua_server, MobileDeviceIdentityAppleAppAttest, value)
      end
    end
  end
end
