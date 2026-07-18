defmodule TamanduaServer.Mobile.MobileMutationAuthorizationRuntimePGTest do
  @moduledoc """
  Destructive PostgreSQL runtime gate for the mobile mutation authorization.

  This suite creates a temporary database role and must run only against an
  explicitly disposable, fully migrated test database. It proves PostgreSQL
  catalog state, enforced tenant isolation, and independent-session consume
  serialization. It is not production or deployment evidence.
  """

  use ExUnit.Case, async: false

  import Ecto.Query
  import TamanduaServer.Factory

  alias Ecto.Adapters.SQL.Sandbox

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileMutationAuthorization,
    MobileMutationProof
  }

  alias TamanduaServer.Repo

  @public_key_spki Base.decode64!(
                     "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
                   )
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"
  @table "mobile_mutation_authorizations"
  @policy "mobile_mutation_authorizations_tenant_isolation"

  if System.get_env("TAMANDUA_MOBILE_MUTATION_RUNTIME_PG_TESTS") != "true" do
    @moduletag skip:
                 "set TAMANDUA_MOBILE_MUTATION_RUNTIME_PG_TESTS=true only for an isolated disposable PostgreSQL database"
  end

  setup_all do
    if System.get_env("TAMANDUA_MOBILE_MUTATION_RUNTIME_PG_TESTS") == "true" do
      role = "tmm_runtime_#{System.unique_integer([:positive])}"

      unboxed(fn ->
        assert {:ok, %{rows: [[true, true, true]]}} =
                 Repo.query(
                   "SELECT current_setting('transaction_read_only') = 'off', role.rolsuper, role.rolcreaterole FROM pg_catalog.pg_roles role WHERE role.rolname = session_user"
                 )

        Repo.query!(
          "CREATE ROLE #{role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS"
        )
      end)

      on_exit(fn ->
        unboxed(fn ->
          Repo.query!("DROP OWNED BY #{role}")
          Repo.query!("DROP ROLE #{role}")
        end)
      end)

      unboxed(fn ->
        Repo.query!("GRANT USAGE ON SCHEMA public TO #{role}")

        Repo.query!("GRANT SELECT, UPDATE ON public.mobile_mutation_authorizations TO #{role}")

        Repo.query!("GRANT SELECT ON public.mobile_device_identity_keys TO #{role}")

        Repo.query!(
          "GRANT SELECT, UPDATE ON public.mobile_device_identity_recovery_intents TO #{role}"
        )

        Repo.query!("GRANT EXECUTE ON FUNCTION public.current_organization_id() TO #{role}")
      end)

      {:ok, role: role}
    else
      :ok
    end
  end

  test "catalog and ordinary-role behavior enforce the exact tenant policy", %{role: role} do
    fixture = create_fixture!()
    other_organization_id = Ecto.UUID.generate()
    cleanup_fixture(fixture.organization_id)

    unboxed(fn ->
      assert {:ok, %{rows: [[true, true]]}} =
               Repo.query(
                 "SELECT relrowsecurity, relforcerowsecurity FROM pg_catalog.pg_class WHERE oid = $1::pg_catalog.regclass",
                 ["public.#{@table}"]
               )

      assert {:ok,
              %{
                rows: [
                  [
                    @policy,
                    "PERMISSIVE",
                    ["public"],
                    "ALL",
                    "(organization_id = current_organization_id())",
                    "(organization_id = current_organization_id())"
                  ]
                ]
              }} =
               Repo.query(
                 "SELECT policyname, permissive, roles, cmd, qual, with_check FROM pg_catalog.pg_policies WHERE schemaname = 'public' AND tablename = $1 ORDER BY policyname",
                 [@table]
               )
    end)

    assert role_contract(role) == {false, false, false, false}

    assert tenant_probe(role, fixture.organization_id, fixture.issued.authorization_id) ==
             {1, 1}

    assert tenant_probe(role, other_organization_id, fixture.issued.authorization_id) ==
             {0, 0}

    assert tenant_probe(role, nil, fixture.issued.authorization_id) == {0, 0}
  end

  test "independent sessions consume once, persist the result, and preserve retry on rollback", %{
    role: role
  } do
    raced = create_fixture!()
    rolled_back = create_fixture!()
    cleanup_fixture(raced.organization_id)
    cleanup_fixture(rolled_back.organization_id)

    raced_proof = signed_proof(raced.issued)
    parent = self()
    barrier = make_ref()

    workers =
      for attempt <- 1..2 do
        Task.async(fn ->
          unboxed(fn ->
            Repo.checkout(fn ->
              Repo.transaction(fn ->
                set_role_and_tenant!(role, raced.organization_id)
                %{rows: [[backend_pid]]} = Repo.query!("SELECT pg_backend_pid()")
                send(parent, {:runtime_worker_ready, barrier, self(), backend_pid})

                receive do
                  {:start_runtime_consume, ^barrier} -> :ok
                after
                  10_000 -> Repo.rollback(:runtime_barrier_timeout)
                end

                MobileMutationProof.consume_and_run(
                  Repo,
                  raced.organization_id,
                  raced.issued.authorization_id,
                  raced_proof,
                  raced.expected,
                  fn _authorization ->
                    {:ok, :created, "raced-device-row", {:attempt, attempt}}
                  end,
                  now: raced.now
                )
              end)
            end)
          end)
        end)
      end

    ready = collect_workers(barrier, 2, [])
    assert ready |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> length() == 2

    Enum.each(ready, fn {worker, _backend_pid} ->
      send(worker, {:start_runtime_consume, barrier})
    end)

    results = Enum.map(workers, &Task.await(&1, 10_000))
    assert Enum.count(results, &match?({:ok, {:ok, _, {:attempt, _}}}, &1)) == 1
    assert Enum.count(results, &match?({:error, :authorization_already_consumed}, &1)) == 1

    persisted = fetch_authorization!(raced)
    assert persisted.result_outcome == "created"
    assert persisted.result_resource_id == "raced-device-row"
    assert persisted.consumed_at == raced.now

    rolled_back_proof = signed_proof(rolled_back.issued)

    assert {:error, :device_write_failed} =
             consume_as_role(role, rolled_back, rolled_back_proof, fn _authorization ->
               {:error, :device_write_failed}
             end)

    retryable = fetch_authorization!(rolled_back)
    refute retryable.consumed_at
    refute retryable.result_outcome
    refute retryable.result_resource_id

    assert {:ok, {:ok, finalized, :retried_projection}} =
             consume_as_role(role, rolled_back, rolled_back_proof, fn _authorization ->
               {:ok, :updated, "retried-device-row", :retried_projection}
             end)

    assert finalized.result_outcome == "updated"
    assert finalized.result_resource_id == "retried-device-row"

    persisted_retry = fetch_authorization!(rolled_back)
    assert persisted_retry.consumed_at == rolled_back.now
    assert persisted_retry.result_outcome == "updated"
    assert persisted_retry.result_resource_id == "retried-device-row"
  end

  defp create_fixture! do
    unboxed(fn ->
      organization = insert(:organization)
      now = DateTime.utc_now() |> DateTime.add(5, :second) |> DateTime.truncate(:microsecond)
      installation_id = "tmm-runtime-#{Ecto.UUID.generate()}"
      resource_id = "device-#{Ecto.UUID.generate()}"

      {:ok, fixture} =
        Repo.transaction(fn ->
          set_tenant!(organization.id)
          key = insert_identity_key!(organization.id, installation_id, now)
          body = %{"device_id" => resource_id, "platform" => "android"}

          expected = %{
            actor_id: "runtime-gate",
            installation_id: installation_id,
            resource_id: resource_id,
            operation: "mobile_device_v2_upsert",
            http_method: "POST",
            route_id: "mobile_v2_devices_upsert",
            body: body
          }

          assert {:ok, issued} =
                   MobileMutationProof.issue(
                     organization.id,
                     %{
                       actor_id: expected.actor_id,
                       installation_id: installation_id,
                       resource_id: resource_id,
                       body: body
                     },
                     now: now
                   )

          %{
            organization_id: organization.id,
            key: key,
            expected: expected,
            issued: issued,
            now: now
          }
        end)

      fixture
    end)
  end

  defp insert_identity_key!(organization_id, installation_id, now) do
    challenge =
      %MobileDeviceIdentityChallenge{}
      |> MobileDeviceIdentityChallenge.changeset(%{
        organization_id: organization_id,
        installation_id: installation_id,
        platform: "android",
        purpose: "enroll",
        key_scope_id: "runtime-scope-#{Ecto.UUID.generate()}",
        challenge_digest: :crypto.strong_rand_bytes(32),
        state: "consumed",
        issued_at: DateTime.add(now, -60, :second),
        expires_at: DateTime.add(now, 240, :second),
        consumed_at: now
      })
      |> Repo.insert!()

    device_key_id =
      "tmdk_v1_" <>
        Base.url_encode64(:crypto.hash(:sha256, organization_id <> @public_key_spki),
          padding: false
        )

    %MobileDeviceIdentityKey{}
    |> MobileDeviceIdentityKey.changeset(%{
      organization_id: organization_id,
      proof_challenge_id: challenge.id,
      installation_id: installation_id,
      platform: "android",
      key_scope_id: challenge.key_scope_id,
      device_key_id: device_key_id,
      public_key_spki: @public_key_spki,
      algorithm: @algorithm,
      proof_state: "verified",
      attestation_state: "not_requested",
      lifecycle_state: "active",
      activated_at: now,
      last_proof_at: now
    })
    |> Repo.insert!()
  end

  defp tenant_probe(role, organization_id, authorization_id) do
    unboxed(fn ->
      assert {:ok, result} =
               Repo.transaction(fn ->
                 Repo.query!("SET LOCAL ROLE #{role}")

                 if organization_id do
                   set_tenant!(organization_id)
                 else
                   Repo.query!("SELECT set_config('app.current_organization_id', '', true)")
                 end

                 %{rows: [[visible]]} =
                   Repo.query!("SELECT count(*) FROM public.mobile_mutation_authorizations")

                 %{num_rows: updated} =
                   Repo.query!(
                     "UPDATE public.mobile_mutation_authorizations SET updated_at = updated_at WHERE id = $1",
                     [authorization_id]
                   )

                 {visible, updated}
               end)

      result
    end)
  end

  defp role_contract(role) do
    unboxed(fn ->
      %{rows: [[can_login, superuser, create_role, bypass_rls]]} =
        Repo.query!(
          "SELECT rolcanlogin, rolsuper, rolcreaterole, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = $1",
          [role]
        )

      {can_login, superuser, create_role, bypass_rls}
    end)
  end

  defp consume_as_role(role, fixture, proof, callback) do
    unboxed(fn ->
      Repo.checkout(fn ->
        Repo.transaction(fn ->
          set_role_and_tenant!(role, fixture.organization_id)

          MobileMutationProof.consume_and_run(
            Repo,
            fixture.organization_id,
            fixture.issued.authorization_id,
            proof,
            fixture.expected,
            callback,
            now: fixture.now
          )
        end)
      end)
    end)
  end

  defp fetch_authorization!(fixture) do
    unboxed(fn ->
      assert {:ok, authorization} =
               Repo.transaction(fn ->
                 set_tenant!(fixture.organization_id)
                 Repo.get!(MobileMutationAuthorization, fixture.issued.authorization_id)
               end)

      authorization
    end)
  end

  defp cleanup_fixture(organization_id) do
    on_exit(fn ->
      unboxed(fn ->
        Repo.delete_all(
          from(organization in TamanduaServer.Accounts.Organization,
            where: organization.id == ^organization_id
          )
        )
      end)
    end)
  end

  defp collect_workers(_barrier, 0, ready), do: ready

  defp collect_workers(barrier, remaining, ready) do
    receive do
      {:runtime_worker_ready, ^barrier, worker, backend_pid} ->
        collect_workers(barrier, remaining - 1, [{worker, backend_pid} | ready])
    after
      10_000 -> flunk("runtime worker readiness timed out")
    end
  end

  defp set_role_and_tenant!(role, organization_id) do
    Repo.query!("SET LOCAL ROLE #{role}")
    set_tenant!(organization_id)
  end

  defp set_tenant!(organization_id) do
    Repo.query!("SELECT set_config('app.current_organization_id', $1, true)", [organization_id])
  end

  defp signed_proof(issued) do
    signature = :public_key.sign(issued.payload, :sha256, decode_private_key(@private_key))

    %{
      challenge_id: issued.challenge_id,
      nonce: issued.nonce,
      signature: Base.url_encode64(signature, padding: false)
    }
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp unboxed(callback), do: Sandbox.unboxed_run(Repo, callback)
end
