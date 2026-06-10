defmodule TamanduaServer.Auth.MFA.TOTP do
  @moduledoc """
  TOTP (Time-based One-Time Password) provider for MFA.
  Implements RFC 6238 TOTP using HMAC-SHA1.
  """

  import Bitwise

  @totp_time_step 30
  @totp_digits 6
  @totp_tolerance 1  # Allow 1 step before/after (90 second window total)

  @doc """
  Generate a new TOTP secret.
  Returns a Base32-encoded 160-bit (20-byte) secret.
  """
  def generate_secret do
    :crypto.strong_rand_bytes(20)
    |> Base.encode32(padding: false)
  end

  @doc """
  Generate a provisioning URI for QR code display.
  """
  def provisioning_uri(secret, label, issuer \\ "Tamandua") do
    encoded_label = URI.encode(label)
    encoded_issuer = URI.encode(issuer)

    "otpauth://totp/#{encoded_issuer}:#{encoded_label}?" <>
      "secret=#{secret}&issuer=#{encoded_issuer}&digits=#{@totp_digits}&period=#{@totp_time_step}"
  end

  @doc """
  Verify a TOTP code against a secret.
  Returns true if the code is valid within the tolerance window.
  """
  def verify(secret, code) when is_binary(secret) and is_binary(code) do
    current_time = System.system_time(:second)
    current_step = div(current_time, @totp_time_step)

    # Check current step and +/- tolerance steps
    Enum.any?(
      (current_step - @totp_tolerance)..(current_step + @totp_tolerance),
      fn step ->
        expected = generate_at_step(secret, step)
        secure_compare(expected, code)
      end
    )
  rescue
    _ -> false
  end

  def verify(_, _), do: false

  @doc """
  Generate a TOTP code for the current time.
  Useful for testing.
  """
  def generate_current(secret) do
    current_time = System.system_time(:second)
    current_step = div(current_time, @totp_time_step)
    generate_at_step(secret, current_step)
  end

  # Generate TOTP at a specific time step (RFC 6238)
  defp generate_at_step(secret, step) do
    # Encode the time step as a big-endian 64-bit integer
    msg = <<step::unsigned-big-integer-size(64)>>

    # Decode the Base32-encoded shared secret
    decoded_secret =
      case Base.decode32(secret, padding: false) do
        {:ok, decoded} -> decoded
        :error -> Base.decode32!(secret)
      end

    # Compute HMAC-SHA1
    hmac = :crypto.mac(:hmac, :sha, decoded_secret, msg)

    # Dynamic truncation (RFC 4226, Section 5.4)
    offset = :binary.at(hmac, 19) &&& 0x0F

    <<_::binary-size(offset), code::unsigned-big-integer-size(32), _::binary>> = hmac
    code = (code &&& 0x7FFFFFFF) |> rem(round(:math.pow(10, @totp_digits)))

    String.pad_leading(Integer.to_string(code), @totp_digits, "0")
  end

  # Constant-time string comparison to prevent timing attacks
  defp secure_compare(a, b) when byte_size(a) != byte_size(b), do: false

  defp secure_compare(a, b) do
    Plug.Crypto.secure_compare(a, b)
  end
end
