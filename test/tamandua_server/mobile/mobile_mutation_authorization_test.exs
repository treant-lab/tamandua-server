defmodule TamanduaServer.Mobile.MobileMutationAuthorizationTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Mobile.{
    MobileDeviceIdentity,
    MobileDeviceIdentityChallenge,
    MobileDeviceIdentityKey,
    MobileDeviceIdentityRecovery,
    MobileMutationAuthorization,
    MobileMutationProof
  }

  @public_key "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC5iM0/c6FZmhIJ1pO/PIsyQ2HqESS7LO/VAgEUL/ZFHugMKNzBWyeCKU+UMqW2ubv2/1WF/AU7vIbj+a8aw/BA=="
  @private_key "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ1B1d3lTMW90U2JsSkREczAKdGVCM2cvK3V5aWJsS3pFeWJxaGVrS3VRTktlaFJBTkNBQVFMbUl6VDl6b1ZtYUVnbldrNzg4aXpKRFllb1JKTApzczc5VUNBUlF2OWtVZTZBd28zTUZiSjRJcFQ1UXlwYmE1dS9iL1ZZWDhCVHU4aHVQNXJ4ckQ4RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
  @algorithm "ecdsa-p256-sha256"
  @now ~U[2026-07-17 18:00:00.000000Z]
  @interoperability_vectors Path.expand(
                              "../../../../../schemas/examples/mobile_device_mutation_authorization_vectors_v1.json",
                              __DIR__
                            )

  setup do
    organization = insert(:organization)
    installation_id = "tmnd-mutation-pop-installation"
    key = bind_key!(organization.id, installation_id, @now)

    body = %{
      "device_id" => "device-v2-001",
      "nested" => %{"z" => 3, "a" => [true, nil, "value"]},
      "platform" => "android"
    }

    expected = %{
      actor_id: "user:operator-001",
      installation_id: installation_id,
      resource_id: body["device_id"],
      operation: "mobile_device_v2_upsert",
      http_method: "POST",
      route_id: "mobile_v2_devices_upsert",
      body: body
    }

    %{organization: organization, key: key, body: body, expected: expected}
  end

  test "matches the shared canonical body and digest corpus" do
    vectors = interoperability_vectors!()
    assert vectors["evidence_class"] == "local_synthetic_contract"

    Enum.each(vectors["canonical_body_vectors"], fn vector ->
      expected_digest = decode_base64url!(vector["body_sha256_base64url"])

      assert :crypto.hash(:sha256, vector["canonical_body"]) == expected_digest

      assert {:ok, ^expected_digest} =
               MobileMutationProof.request_body_sha256(vector["body"])
    end)
  end

  test "matches the shared accepted boundary and rejection descriptors" do
    vectors = interoperability_vectors!()

    Enum.each(vectors["boundary_descriptors"], fn descriptor ->
      body = body_from_descriptor(descriptor)

      if expected_bytes = descriptor["expected_canonical_utf8_bytes"] do
        encoded = Jason.encode!(body)
        assert byte_size(encoded) == expected_bytes

        assert :crypto.hash(:sha256, encoded) ==
                 decode_base64url!(descriptor["body_sha256_base64url"])
      end

      assert {:ok, _digest} = MobileMutationProof.request_body_sha256(body)
    end)

    Enum.each(vectors["rejection_descriptors"], fn descriptor ->
      body = body_from_descriptor(descriptor)

      if expected_bytes = descriptor["expected_canonical_utf8_bytes"] do
        encoded = Jason.encode!(body)
        assert byte_size(encoded) == expected_bytes

        assert :crypto.hash(:sha256, encoded) ==
                 decode_base64url!(descriptor["body_sha256_base64url"])
      end

      assert {:error, :invalid_request_body} = MobileMutationProof.request_body_sha256(body)
    end)
  end

  test "matches the shared exact 20-field payload and payload digest" do
    vector = interoperability_vectors!()["signed_payload_vector"]
    fields = vector["signed_fields"]
    {:ok, issued_at, 0} = DateTime.from_iso8601(fields["issued_at"])
    {:ok, expires_at, 0} = DateTime.from_iso8601(fields["expires_at"])

    authorization = %MobileMutationAuthorization{
      organization_id: fields["organization_id"],
      actor_id: fields["actor_id"],
      installation_id: fields["installation_id"],
      platform: fields["platform"],
      device_key_id: fields["device_key_id"],
      key_scope_id: fields["key_scope_id"],
      request_id: fields["request_id"],
      operation: fields["operation"],
      http_method: fields["http_method"],
      route_id: fields["route_id"],
      resource_id: fields["resource_id"],
      body_sha256: decode_base64url!(fields["body_sha256"]),
      algorithm: fields["algorithm"],
      issued_at: issued_at,
      expires_at: expires_at
    }

    payload =
      MobileMutationProof.canonical_payload(
        authorization,
        fields["challenge_id"],
        fields["nonce"]
      )

    assert map_size(fields) == 20

    assert MobileMutationProof.signed_fields(
             authorization,
             fields["challenge_id"],
             fields["nonce"]
           ) == fields

    assert payload == vector["canonical_payload"]
    assert :crypto.hash(:sha256, payload) == decode_base64url!(vector["payload_sha256_base64url"])
  end

  test "issues a canonical authorization while persisting only domain-separated secret digests",
       context do
    reordered = %{
      "platform" => "android",
      "nested" => %{"a" => [true, nil, "value"], "z" => 3},
      "device_id" => "device-v2-001"
    }

    assert {:ok, digest} = MobileMutationProof.request_body_sha256(context.body)
    assert {:ok, ^digest} = MobileMutationProof.request_body_sha256(reordered)
    issued = issue!(context)
    authorization = Repo.get!(MobileMutationAuthorization, issued.authorization_id)

    assert authorization.identity_key_id == context.key.id
    assert authorization.actor_id == context.expected.actor_id
    assert authorization.resource_id == context.expected.resource_id
    assert authorization.body_sha256 == digest
    assert authorization.expires_at == DateTime.add(@now, 120, :second)
    assert authorization.challenge_digest != :crypto.hash(:sha256, issued.challenge_id)
    assert authorization.nonce_digest != :crypto.hash(:sha256, issued.nonce)
    refute inspect(authorization) =~ issued.challenge_id
    refute inspect(authorization) =~ issued.nonce

    assert issued.payload ==
             MobileMutationProof.canonical_payload(
               authorization,
               issued.challenge_id,
               issued.nonce
             )

    assert issued.signed_fields ==
             MobileMutationProof.signed_fields(
               authorization,
               issued.challenge_id,
               issued.nonce
             )

    assert map_size(issued.signed_fields) == 20

    lines = String.split(issued.payload, "\n")
    assert length(lines) == 20
    refute String.ends_with?(issued.payload, "\n")

    assert Enum.map(lines, &(&1 |> String.split("=", parts: 2) |> hd())) == [
             "protocol",
             "message_type",
             "message_version",
             "organization_id",
             "actor_id",
             "installation_id",
             "platform",
             "device_key_id",
             "key_scope_id",
             "request_id",
             "challenge_id",
             "nonce",
             "operation",
             "http_method",
             "route_id",
             "resource_id",
             "body_sha256",
             "algorithm",
             "issued_at",
             "expires_at"
           ]
  end

  test "rejects tampered body, logical route, resource, and authenticated actor before consume",
       context do
    issued = issue!(context)
    proof = signed_proof(issued)

    tampered = [
      put_in(context.expected.body["platform"], "ios"),
      context.expected
      |> put_in([:body, "platform"], "ios")
      |> Map.put(
        :body_sha256,
        Repo.get!(MobileMutationAuthorization, issued.authorization_id).body_sha256
      ),
      %{context.expected | route_id: "POST:/mobile/v2/devices"},
      %{context.expected | resource_id: "another-device"},
      %{context.expected | actor_id: "user:another-operator"}
    ]

    Enum.each(tampered, fn expected ->
      assert {:error, :authorization_binding_mismatch} =
               consume(context, issued, proof, expected)
    end)

    assert {:ok, consumed} = consume(context, issued, proof, context.expected)
    assert consumed.consumed_at == @now
  end

  test "bounds canonical request bodies by shape, depth, and encoded size" do
    atom_key = %{device_id: "not-a-wire-json-object"}
    too_large = %{"payload" => String.duplicate("x", 65_537)}
    too_many_entries = %{"items" => Enum.to_list(1..2_048)}
    exact_entry_boundary = %{"items" => Enum.to_list(1..2_047)}

    too_deep =
      Enum.reduce(1..17, "leaf", fn depth, nested -> %{"level-#{depth}" => nested} end)

    exact_depth_boundary =
      Enum.reduce(1..16, "leaf", fn depth, nested -> %{"level-#{depth}" => nested} end)

    assert {:error, :invalid_request_body} = MobileMutationProof.request_body_sha256(atom_key)
    assert {:error, :invalid_request_body} = MobileMutationProof.request_body_sha256(too_large)
    assert {:error, :invalid_request_body} = MobileMutationProof.request_body_sha256(too_deep)

    assert {:error, :invalid_request_body} =
             MobileMutationProof.request_body_sha256(too_many_entries)

    assert {:ok, _digest} = MobileMutationProof.request_body_sha256(exact_entry_boundary)
    assert {:ok, _digest} = MobileMutationProof.request_body_sha256(exact_depth_boundary)

    assert {:error, :invalid_request_body} =
             MobileMutationProof.request_body_sha256(%{"value" => 1.0})

    assert {:error, :invalid_request_body} =
             MobileMutationProof.request_body_sha256(%{"value" => 9_007_199_254_740_992})

    assert {:ok, _digest} =
             MobileMutationProof.request_body_sha256(%{"value" => 9_007_199_254_740_991})
  end

  test "rejects dangerous/control keys and sorts valid Unicode by code point" do
    for key <- ["__proto__", "constructor", "prototype", "c0\u0001", "c1\u0080"] do
      assert {:error, :invalid_request_body} =
               MobileMutationProof.request_body_sha256(%{"nested" => %{key => true}})
    end

    expected = :crypto.hash(:sha256, ~s({"a":3,"é":2,"😀":1}))

    assert {:ok, ^expected} =
             MobileMutationProof.request_body_sha256(%{"😀" => 1, "é" => 2, "a" => 3})

    assert {:error, :invalid_request_body} =
             MobileMutationProof.request_body_sha256(%{
               "device_id" => "device-v2-001",
               "mutation_authorization" => %{}
             })
  end

  test "fails closed for expiry, invalid signature, and transactionless consumption", context do
    issued = issue!(context, ttl: 30)
    proof = signed_proof(issued)

    assert {:error, :transaction_required} =
             MobileMutationProof.consume(
               Repo,
               context.organization.id,
               issued.authorization_id,
               proof,
               context.expected,
               now: @now
             )

    invalid_proof = %{proof | signature: base64url(:crypto.strong_rand_bytes(64))}

    assert {:error, :invalid_signature} =
             consume(context, issued, invalid_proof, context.expected)

    assert {:error, :authorization_expired} =
             consume(context, issued, proof, context.expected,
               now: DateTime.add(@now, 30, :second)
             )
  end

  test "clock rollback cannot consume or invoke the mutation callback", context do
    issued = issue!(context)
    proof = signed_proof(issued)
    before_issue = DateTime.add(@now, -1, :microsecond)

    assert {:error, :authorization_not_yet_valid} =
             Repo.transaction(fn ->
               MobileMutationProof.consume_and_run(
                 Repo,
                 context.organization.id,
                 issued.authorization_id,
                 proof,
                 context.expected,
                 fn _authorization -> flunk("not-yet-valid callback must not run") end,
                 now: before_issue
               )
             end)

    authorization = Repo.get!(MobileMutationAuthorization, issued.authorization_id)
    refute authorization.consumed_at
    refute authorization.result_outcome
    refute authorization.result_resource_id
  end

  test "rejects non-canonical server-derived signed bindings", context do
    for {field, value} <- [actor_id: " actor", installation_id: "install\u0001", resource_id: ""] do
      attrs = %{
        actor_id: context.expected.actor_id,
        installation_id: context.expected.installation_id,
        resource_id: context.expected.resource_id,
        body: context.body
      }

      assert {:error, {:invalid_field, ^field}} =
               MobileMutationProof.issue(
                 context.organization.id,
                 Map.put(attrs, field, value),
                 now: @now
               )
    end
  end

  test "rejects an authorization after its bound key is revoked or rotated", context do
    Enum.each(["revoked", "rotated"], fn lifecycle_state ->
      issued = issue!(context)

      Repo.update_all(
        from(key in MobileDeviceIdentityKey, where: key.id == ^context.key.id),
        set: [lifecycle_state: lifecycle_state]
      )

      assert {:error, :identity_key_snapshot_inactive} =
               consume(context, issued, signed_proof(issued), context.expected)

      Repo.update_all(
        from(key in MobileDeviceIdentityKey, where: key.id == ^context.key.id),
        set: [lifecycle_state: "active"]
      )
    end)
  end

  test "a live identity recovery intent blocks both issue and consume", context do
    issued_before_recovery = issue!(context)

    assert {:ok, _recovery} =
             MobileDeviceIdentityRecovery.issue(
               context.organization.id,
               %{
                 installation_id: context.expected.installation_id,
                 purpose: "rebind",
                 old_device_key_id: context.key.device_key_id,
                 reason: "operator recovery test"
               },
               now: @now,
               ttl_seconds: 60
             )

    assert {:error, :identity_recovery_in_progress} =
             MobileMutationProof.issue(
               context.organization.id,
               %{
                 actor_id: context.expected.actor_id,
                 installation_id: context.expected.installation_id,
                 resource_id: context.expected.resource_id,
                 body: context.body
               },
               now: @now
             )

    assert {:error, :identity_recovery_in_progress} =
             consume(
               context,
               issued_before_recovery,
               signed_proof(issued_before_recovery),
               context.expected
             )
  end

  test "a proof is consumed once under sequential replay and concurrent attempts", context do
    first = issue!(context)
    first_proof = signed_proof(first)
    assert {:ok, _authorization} = consume(context, first, first_proof, context.expected)

    assert {:error, :authorization_already_consumed} =
             consume(context, first, first_proof, context.expected)

    concurrent = issue!(context)
    concurrent_proof = signed_proof(concurrent)
    test_pid = self()

    tasks =
      1..2
      |> Enum.map(fn _attempt ->
        Task.async(fn ->
          send(test_pid, {:attempt_ready, self()})
          receive do: (:go -> :ok)

          consume(
            context,
            concurrent,
            concurrent_proof,
            context.expected
          )
        end)
      end)

    assert_receive {:attempt_ready, first_pid}
    assert_receive {:attempt_ready, second_pid}
    send(first_pid, :go)
    send(second_pid, :go)
    results = Enum.map(tasks, &Task.await(&1, 5_000))
    assert Enum.count(results, &match?({:ok, _}, &1)) == 1

    assert Enum.count(
             results,
             &match?({:error, :authorization_already_consumed}, &1)
           ) == 1
  end

  test "callback failure rolls back consume and successful retry stores a durable result",
       context do
    issued = issue!(context)
    proof = signed_proof(issued)

    assert {:error, :device_write_failed} =
             Repo.transaction(fn ->
               MobileMutationProof.consume_and_run(
                 Repo,
                 context.organization.id,
                 issued.authorization_id,
                 proof,
                 context.expected,
                 fn _authorization -> {:error, :device_write_failed} end,
                 now: @now
               )
             end)

    refute Repo.get!(MobileMutationAuthorization, issued.authorization_id).consumed_at

    assert {:ok, {:ok, finalized, :device_projection}} =
             Repo.transaction(fn ->
               MobileMutationProof.consume_and_run(
                 Repo,
                 context.organization.id,
                 issued.authorization_id,
                 proof,
                 context.expected,
                 fn _authorization ->
                   {:ok, :created, "device-v2-row-001", :device_projection}
                 end,
                 now: @now
               )
             end)

    assert finalized.result_outcome == "created"
    assert finalized.result_resource_id == "device-v2-row-001"

    persisted = Repo.get!(MobileMutationAuthorization, issued.authorization_id)
    assert persisted.consumed_at == @now
    assert persisted.result_outcome == "created"
    assert persisted.result_resource_id == "device-v2-row-001"
  end

  defp issue!(context, opts \\ []) do
    attrs = %{
      actor_id: context.expected.actor_id,
      installation_id: context.expected.installation_id,
      resource_id: context.expected.resource_id,
      body: context.body,
      body_sha256: :crypto.strong_rand_bytes(32)
    }

    assert {:ok, issued} =
             MobileMutationProof.issue(
               context.organization.id,
               attrs,
               Keyword.merge([now: @now], opts)
             )

    issued
  end

  defp consume(context, issued, proof, expected, opts \\ []) do
    Repo.transaction(fn ->
      case MobileMutationProof.consume(
             Repo,
             context.organization.id,
             issued.authorization_id,
             proof,
             expected,
             Keyword.merge([now: @now], opts)
           ) do
        {:ok, authorization} -> authorization
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
  end

  defp signed_proof(issued) do
    signature = :public_key.sign(issued.payload, :sha256, decode_private_key(@private_key))

    %{
      challenge_id: issued.challenge_id,
      nonce: issued.nonce,
      signature: base64url(signature)
    }
  end

  defp bind_key!(organization_id, installation_id, now) do
    assert {:ok, issued} =
             MobileDeviceIdentity.issue_challenge(
               organization_id,
               %{installation_id: installation_id, platform: "android", purpose: "enroll"},
               now: now
             )

    challenge = Repo.get!(MobileDeviceIdentityChallenge, issued.challenge_id)
    spki = Base.decode64!(@public_key)
    device_key_id = MobileDeviceIdentity.derive_device_key_id(organization_id, spki)

    payload =
      MobileDeviceIdentity.canonical_payload(
        challenge,
        issued.challenge,
        device_key_id,
        @algorithm
      )

    proof = %{
      challenge_id: issued.challenge_id,
      challenge: issued.challenge,
      installation_id: installation_id,
      platform: "android",
      purpose: "enroll",
      key_scope_id: issued.key_scope_id,
      algorithm: @algorithm,
      public_key_spki: base64url(spki),
      device_key_id: device_key_id,
      signature:
        payload
        |> :public_key.sign(:sha256, decode_private_key(@private_key))
        |> base64url()
    }

    assert {:ok, key} = MobileDeviceIdentity.verify_and_bind(organization_id, proof, now: now)
    key
  end

  defp decode_private_key(encoded) do
    encoded
    |> Base.decode64!()
    |> :public_key.pem_decode()
    |> hd()
    |> :public_key.pem_entry_decode()
  end

  defp interoperability_vectors! do
    @interoperability_vectors
    |> File.read!()
    |> Jason.decode!()
  end

  defp body_from_descriptor(%{"constructor" => "integer_decimal", "value" => value}),
    do: %{"value" => String.to_integer(value)}

  defp body_from_descriptor(%{"constructor" => "fractional_number", "value" => value}),
    do: %{"value" => String.to_float(value)}

  defp body_from_descriptor(%{"constructor" => "nested_object_depth", "value" => depth}) do
    Enum.reduce(1..depth, "leaf", fn _level, nested -> %{"nested" => nested} end)
  end

  defp body_from_descriptor(%{
         "constructor" => "array_entry_count_with_root_key",
         "value" => count
       }),
       do: %{"items" => Enum.to_list(0..(count - 1))}

  defp body_from_descriptor(%{"constructor" => "reserved_mutation_authorization_field"}),
    do: %{"mutation_authorization" => %{}}

  defp body_from_descriptor(%{"constructor" => "forbidden_key", "value" => key}),
    do: %{key => true}

  defp body_from_descriptor(%{"constructor" => "control_key", "value" => key}),
    do: %{key => true}

  defp body_from_descriptor(%{
         "constructor" => "canonical_utf8_size",
         "character" => character,
         "repeat_count" => repeat_count,
         "suffix" => suffix
       }) do
    suffix_value =
      case suffix do
        "none" -> ""
        "newline" -> "\n"
        "newline_then_ascii" -> "\nx"
      end

    %{"payload" => String.duplicate(character, repeat_count) <> suffix_value}
  end

  defp body_from_descriptor(%{
         "constructor" => "isolated_unicode_scalar",
         "surrogate" => surrogate,
         "location" => location
       }) do
    invalid_utf8 =
      if surrogate == "high",
        do: <<0xED, 0xA0, 0x80>>,
        else: <<0xED, 0xB0, 0x80>>

    if location == "object_key",
      do: %{"nested" => %{invalid_utf8 => true}},
      else: %{"nested" => %{"value" => invalid_utf8}}
  end

  defp decode_base64url!(value), do: Base.url_decode64!(value, padding: false)

  defp base64url(value), do: Base.url_encode64(value, padding: false)
end
