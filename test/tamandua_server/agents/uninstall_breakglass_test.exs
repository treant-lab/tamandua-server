defmodule TamanduaServer.Agents.UninstallBreakglassTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Agents.{AgentUninstallBreakglassIssuance, UninstallBreakglass}

  @fixture_path Path.expand(
                  "../../../../../tools/detection_validation/fixtures/agent_uninstall_breakglass_v1.json",
                  __DIR__
                )
  @organization_id "44444444-4444-4444-8444-444444444444"
  @agent_id "11111111-1111-4111-8111-111111111111"
  @issuer_id "33333333-3333-4333-8333-333333333333"
  @intent_id "22222222-2222-4222-8222-222222222222"
  @issued_at ~U[2030-01-02 03:04:05Z]
  @seed Base.url_decode64!("indcFSfIJ0V4xWnI-db3XVlYJtfbjRDJaqbnp-KjeO8", padding: false)
  @nonce Base.url_decode64!("cz2IuIRcPQKFRZ-Q4aCDeSP9dobnJDo7e5TjR8DDxq8", padding: false)

  test "emits deterministic canonical bytes and a directly verifiable dedicated signature" do
    parent = self()

    assert {:ok, envelope} =
             issue(
               %{},
               recorder: fn issuance ->
                 send(parent, {:issuance, issuance})
                 :ok
               end
             )

    assert {:ok, payload_bytes} = Base.url_decode64(envelope.payload, padding: false)
    assert {:ok, signature} = Base.url_decode64(envelope.signature, padding: false)
    assert byte_size(signature) == 64

    fixture = @fixture_path |> File.read!() |> Jason.decode!()
    assert envelope.payload == fixture["canonical_payload_base64url"]
    assert envelope.payload == fixture["envelope"]["payload"]
    assert envelope.signature == fixture["envelope"]["signature"]
    assert byte_size(payload_bytes) == 713

    {public_key, _derived_private} = :crypto.generate_key(:eddsa, :ed25519, @seed)
    assert Base.url_encode64(public_key, padding: false) == fixture["test_key"]["public_key_base64url"]

    assert :crypto.verify(
             :eddsa,
             :none,
             UninstallBreakglass.domain_prefix() <> payload_bytes,
             signature,
             [public_key, :ed25519]
           )

    assert_receive {:issuance, issuance}
    assert issuance.intent_id == @intent_id
    assert issuance.organization_id == @organization_id
    assert issuance.agent_id == @agent_id
    assert issuance.issued_by_user_id == @issuer_id
    assert issuance.reason == "Synthetic test-only isolated endpoint recovery authorization"
    assert issuance.platform == "windows"
    assert issuance.consumer == "windows_msi"
    assert issuance.key_id == "test-only-loop67-ed25519-v1"
    assert byte_size(issuance.payload_sha256) == 32
    assert byte_size(issuance.nonce_sha256) == 32
    refute inspect(issuance) =~ Base.url_encode64(@nonce, padding: false)
    refute inspect(issuance) =~ envelope.signature
    refute inspect(issuance) =~ envelope.payload
  end

  test "keyring fails closed for missing, placeholder, duplicate, unknown and legacy keys" do
    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: nil)

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(
               private_keys_json: keyring(:binary.copy(<<0>>, 32))
             )

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(
               private_keys_json: keyring(:crypto.strong_rand_bytes(64))
             )

    duplicate =
      Jason.encode!(%{
        "active_key_id" => "test-only-loop67-ed25519-v1",
        "keys" => [
          key_entry("test-only-loop67-ed25519-v1", @seed),
          key_entry("test-only-loop67-ed25519-v1", :crypto.strong_rand_bytes(32))
        ]
      })

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: duplicate)

    unknown =
      Jason.encode!(%{
        "active_key_id" => "breakglass-missing",
        "keys" => [key_entry("test-only-loop67-ed25519-v1", @seed)]
      })

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: unknown)

    extra =
      Jason.encode!(%{
        "active_key_id" => "test-only-loop67-ed25519-v1",
        "keys" => [key_entry("test-only-loop67-ed25519-v1", @seed)],
        "update_private_key" => Base.url_encode64(@seed, padding: false)
      })

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: extra)

    duplicate_outer =
      ~s({"active_key_id":"test-only-loop67-ed25519-v1","active_key_id":"other","keys":[]})

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: duplicate_outer)

    private_key = Base.url_encode64(@seed, padding: false)

    duplicate_nested =
      ~s({"active_key_id":"test-only-loop67-ed25519-v1","keys":[{"key_id":"test-only-loop67-ed25519-v1","key_id":"other","private_key":"#{private_key}"}]})

    assert {:error, :signer_unavailable} =
             UninstallBreakglass.load_active_key(private_keys_json: duplicate_nested)
  end

  test "enforces reason, binding and maximum lifetime before recording" do
    refute_issue(%{reason: " short "}, :request_invalid)
    refute_issue(%{reason: "bad\nreason"}, :request_invalid)
    refute_issue(%{ttl_seconds: 86_401}, :request_invalid)
    refute_issue(%{platform: "android"}, :request_invalid)
    refute_issue(%{platform: "linux", consumer: "windows_msi"}, :request_invalid)
    refute_issue(%{consumer: "shell"}, :request_invalid)

    assert {:ok, envelope} = issue(%{ttl_seconds: 86_400})
    {:ok, payload} = Base.url_decode64(envelope.payload, padding: false)
    assert Jason.decode!(payload)["expires_at"] == "2030-01-03T03:04:05Z"

    assert {:ok, _native_linux} = issue(%{platform: "linux", consumer: "native_cli"})
  end

  test "authorization and authoritative issuance-store failures suppress the envelope" do
    assert {:error, :agent_not_found} =
             issue(%{}, authorizer: fn _, _, _ -> {:error, :agent_not_found} end)

    assert {:error, :store_unavailable} =
             issue(%{}, recorder: fn _ -> {:error, :down} end)
  end

  test "authoritative issuance changeset rejects sub-second timestamps" do
    {:ok, issued_at, 0} = DateTime.from_iso8601("2030-01-02T03:04:05.000001Z")

    changeset =
      AgentUninstallBreakglassIssuance.issuance_changeset(
        %AgentUninstallBreakglassIssuance{},
        %{
          intent_id: @intent_id,
          organization_id: @organization_id,
          agent_id: @agent_id,
          issued_by_user_id: @issuer_id,
          platform: "windows",
          consumer: "windows_msi",
          reason: "Approved maintenance window",
          key_id: "breakglass-time-test-v1",
          issued_at: issued_at,
          not_before: ~U[2030-01-02 03:04:06Z],
          expires_at: ~U[2030-01-02 04:04:05Z],
          nonce_sha256: :crypto.hash(:sha256, @nonce),
          payload_sha256: :crypto.hash(:sha256, "payload")
        }
      )

    refute changeset.valid?
    assert {:expires_at, {"invalid issuance window", _opts}} =
             Enum.find(changeset.errors, fn {field, _error} -> field == :expires_at end)
  end

  defp issue(attrs, overrides \\ []) do
    attrs =
      Map.merge(
        %{
          reason: "Synthetic test-only isolated endpoint recovery authorization",
          platform: "windows",
          consumer: "windows_msi"
        },
        attrs
      )

    opts =
      [
        private_keys_json: keyring(@seed),
        now: @issued_at,
        intent_id: @intent_id,
        nonce_bytes: @nonce,
        authorizer: fn _, _, _ -> :ok end,
        recorder: fn _ -> :ok end
      ]
      |> Keyword.merge(overrides)

    UninstallBreakglass.issue(@organization_id, @agent_id, @issuer_id, attrs, opts)
  end

  defp refute_issue(overrides, error) do
    assert {:error, ^error} = issue(overrides)
  end

  defp keyring(seed) do
    Jason.encode!(%{
      "active_key_id" => "test-only-loop67-ed25519-v1",
      "keys" => [key_entry("test-only-loop67-ed25519-v1", seed)]
    })
  end

  defp key_entry(id, seed) do
    %{
      "key_id" => id,
      "private_key" => Base.url_encode64(seed, padding: false)
    }
  end
end
