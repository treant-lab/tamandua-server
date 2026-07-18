defmodule TamanduaServer.Auth.MFA.WebAuthn do
  @moduledoc """
  WebAuthn/FIDO2 provider for MFA.
  Supports hardware keys (YubiKey, etc.) and platform authenticators.
  """

  require Logger

  @rp_id "tamandua.security"  # Replace with your actual domain
  @rp_name "Tamandua EDR"
  @timeout 60_000  # 60 seconds

  @doc """
  Generate registration challenge for WebAuthn enrollment.
  Returns a challenge and options for navigator.credentials.create().
  """
  def generate_registration_challenge(user) do
    challenge = :crypto.strong_rand_bytes(32)

    options = %{
      challenge: Base.url_encode64(challenge, padding: false),
      rp: %{
        id: @rp_id,
        name: @rp_name
      },
      user: %{
        id: Base.url_encode64(user.id, padding: false),
        name: user.email,
        displayName: user.name || user.email
      },
      pubKeyCredParams: [
        %{type: "public-key", alg: -7},   # ES256 (ECDSA w/ SHA-256)
        %{type: "public-key", alg: -257}  # RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
      ],
      authenticatorSelection: %{
        authenticatorAttachment: "cross-platform",  # Hardware keys preferred
        userVerification: "preferred",
        residentKey: "preferred"
      },
      timeout: @timeout,
      attestation: "none"  # Don't require attestation
    }

    {:ok, challenge, options}
  end

  @doc """
  Verify WebAuthn registration response.
  Returns {:ok, credential_data} on success.
  """
  def verify_registration(challenge, response) do
    # In a real implementation, you would use the Wax library to verify
    # the attestation object and client data JSON
    #
    # For now, this is a simplified placeholder
    # Install wax via mix.exs: {:wax, "~> 0.6"}

    try do
      # Parse attestation response
      client_data_json = response["clientDataJSON"] |> Base.url_decode64!(padding: false)
      attestation_object = response["attestationObject"] |> Base.url_decode64!(padding: false)

      # Verify client data
      client_data = Jason.decode!(client_data_json)

      with :ok <- verify_client_data_type(client_data, "webauthn.create"),
           :ok <- verify_challenge(client_data, challenge),
           :ok <- verify_origin(client_data),
           {:ok, auth_data} <- parse_attestation_object(attestation_object) do
        {:ok, auth_data}
      else
        {:error, reason} -> {:error, reason}
      end
    rescue
      error ->
        Logger.error("WebAuthn registration verification failed: #{inspect(error)}")
        {:error, :invalid_response}
    end
  end

  @doc """
  Generate authentication challenge for WebAuthn login.
  """
  def generate_authentication_challenge(credentials) do
    challenge = :crypto.strong_rand_bytes(32)

    # Build list of allowed credentials
    allow_credentials =
      Enum.map(credentials, fn cred ->
        %{
          type: "public-key",
          id: Base.url_encode64(cred.credential_id, padding: false),
          transports: cred.transports || []
        }
      end)

    options = %{
      challenge: Base.url_encode64(challenge, padding: false),
      rpId: @rp_id,
      allowCredentials: allow_credentials,
      userVerification: "preferred",
      timeout: @timeout
    }

    {:ok, challenge, options}
  end

  @doc """
  Verify WebAuthn authentication response.
  Returns {:ok, credential} on success.
  """
  def verify_authentication(challenge, response, credential) do
    # In a real implementation, use Wax library
    try do
      client_data_json = response["clientDataJSON"] |> Base.url_decode64!(padding: false)
      authenticator_data = response["authenticatorData"] |> Base.url_decode64!(padding: false)
      signature = response["signature"] |> Base.url_decode64!(padding: false)

      client_data = Jason.decode!(client_data_json)

      with :ok <- verify_client_data_type(client_data, "webauthn.get"),
           :ok <- verify_challenge(client_data, challenge),
           :ok <- verify_origin(client_data),
           :ok <- verify_signature(authenticator_data, client_data_json, signature, credential) do
        # Update signature counter to prevent replay attacks
        new_counter = extract_counter(authenticator_data)
        {:ok, credential, new_counter}
      else
        {:error, reason} -> {:error, reason}
      end
    rescue
      error ->
        Logger.error("WebAuthn authentication verification failed: #{inspect(error)}")
        {:error, :invalid_response}
    end
  end

  # Private helper functions

  defp verify_client_data_type(client_data, expected_type) do
    if client_data["type"] == expected_type do
      :ok
    else
      {:error, :invalid_client_data_type}
    end
  end

  defp verify_challenge(client_data, expected_challenge) do
    challenge_b64 = Base.url_encode64(expected_challenge, padding: false)

    if client_data["challenge"] == challenge_b64 do
      :ok
    else
      {:error, :challenge_mismatch}
    end
  end

  defp verify_origin(client_data) do
    # In production, verify against your actual origin
    expected_origin = "https://#{@rp_id}"

    if client_data["origin"] == expected_origin do
      :ok
    else
      Logger.warning("Origin mismatch: expected #{expected_origin}, got #{client_data["origin"]}")
      # For development, allow localhost
      if String.contains?(client_data["origin"], "localhost") do
        :ok
      else
        {:error, :origin_mismatch}
      end
    end
  end

  defp parse_attestation_object(_attestation_object) do
    # This is a simplified placeholder
    # In production, use Wax.Metadata to parse CBOR and extract auth data
    {:ok,
     %{
       credential_id: :crypto.strong_rand_bytes(16),
       public_key: :crypto.strong_rand_bytes(64),
       aaguid: :crypto.strong_rand_bytes(16),
       counter: 0
     }}
  end

  defp verify_signature(_authenticator_data, _client_data_json, _signature, _credential) do
    # This is a simplified placeholder
    # In production, reconstruct the signed data and verify using the public key
    # signed_data = authenticator_data <> :crypto.hash(:sha256, client_data_json)
    # Verify signature using credential.public_key

    # For now, just accept
    :ok
  end

  defp extract_counter(authenticator_data) do
    # Counter is bytes 33-36 of authenticator data (big-endian uint32)
    <<_::binary-size(33), counter::unsigned-big-integer-size(32), _::binary>> = authenticator_data
    counter
  rescue
    _ -> 0
  end
end
