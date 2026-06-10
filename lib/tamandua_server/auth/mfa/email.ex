defmodule TamanduaServer.Auth.MFA.Email do
  @moduledoc """
  Email provider for MFA.
  Sends verification codes via email.
  """

  require Logger
  import Swoosh.Email

  @code_length 6
  @code_ttl 300  # 5 minutes in seconds
  @rate_limit_window 60  # 1 minute
  @rate_limit_max 3  # Max 3 emails per minute per address

  @doc """
  Generate a random 6-digit email code.
  """
  def generate_code do
    :rand.uniform(999999)
    |> Integer.to_string()
    |> String.pad_leading(@code_length, "0")
  end

  @doc """
  Send an email code to an email address.
  Returns {:ok, code} on success, {:error, reason} on failure.
  """
  def send_code(email_address) do
    with :ok <- check_rate_limit(email_address),
         code <- generate_code(),
         :ok <- deliver_email(email_address, code) do
      record_send(email_address)
      {:ok, code}
    else
      {:error, :rate_limited} = error ->
        Logger.warning("Email rate limit exceeded for #{mask_email(email_address)}")
        error

      {:error, reason} = error ->
        Logger.error("Failed to send email to #{mask_email(email_address)}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Verify an email code.
  """
  def verify(stored_code, stored_code_sent_at, provided_code) do
    with true <- code_not_expired?(stored_code_sent_at),
         true <- codes_match?(stored_code, provided_code) do
      true
    else
      _ -> false
    end
  end

  # Deliver email via Swoosh
  defp deliver_email(email_address, code) do
    email =
      new()
      |> to(email_address)
      |> from({"Tamandua Security", "noreply@tamandua.security"})
      |> subject("Your Tamandua Verification Code")
      |> html_body(email_html_body(code))
      |> text_body(email_text_body(code))

    case TamanduaServer.Mailer.deliver(email) do
      {:ok, _metadata} ->
        :ok

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp email_html_body(code) do
    """
    <html>
      <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">Tamandua Security Verification</h2>
        <p>Your verification code is:</p>
        <div style="background-color: #f4f4f4; padding: 15px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
          #{code}
        </div>
        <p style="color: #666;">This code will expire in 5 minutes.</p>
        <p style="color: #666; font-size: 12px;">If you did not request this code, please ignore this email or contact your administrator.</p>
      </body>
    </html>
    """
  end

  defp email_text_body(code) do
    """
    Tamandua Security Verification

    Your verification code is: #{code}

    This code will expire in 5 minutes.

    If you did not request this code, please ignore this email or contact your administrator.
    """
  end

  defp code_not_expired?(nil), do: false

  defp code_not_expired?(sent_at) do
    now = DateTime.utc_now()
    diff = DateTime.diff(now, sent_at, :second)
    diff <= @code_ttl
  end

  defp codes_match?(nil, _), do: false
  defp codes_match?(_, nil), do: false

  defp codes_match?(stored, provided) do
    stored_hash = hash_code(stored)
    Bcrypt.verify_pass(provided, stored_hash)
  end

  @doc """
  Hash an email code for storage.
  """
  def hash_code(code) do
    Bcrypt.hash_pwd_salt(code)
  end

  # Rate limiting using ETS
  @rate_limit_table :email_mfa_rate_limits

  defp ensure_rate_limit_table do
    case :ets.whereis(@rate_limit_table) do
      :undefined ->
        :ets.new(@rate_limit_table, [:set, :public, :named_table])

      _ ->
        :ok
    end
  end

  defp check_rate_limit(email_address) do
    ensure_rate_limit_table()
    now = System.system_time(:second)
    key = hash_email(email_address)

    case :ets.lookup(@rate_limit_table, key) do
      [{^key, count, window_start}] ->
        if now - window_start > @rate_limit_window do
          :ets.delete(@rate_limit_table, key)
          :ok
        else
          if count >= @rate_limit_max do
            {:error, :rate_limited}
          else
            :ok
          end
        end

      [] ->
        :ok
    end
  end

  defp record_send(email_address) do
    ensure_rate_limit_table()
    now = System.system_time(:second)
    key = hash_email(email_address)

    case :ets.lookup(@rate_limit_table, key) do
      [{^key, count, window_start}] ->
        if now - window_start > @rate_limit_window do
          :ets.insert(@rate_limit_table, {key, 1, now})
        else
          :ets.insert(@rate_limit_table, {key, count + 1, window_start})
        end

      [] ->
        :ets.insert(@rate_limit_table, {key, 1, now})
    end
  end

  defp hash_email(email_address) do
    :crypto.hash(:sha256, email_address) |> Base.encode16()
  end

  defp mask_email(email_address) do
    case String.split(email_address, "@") do
      [local, domain] ->
        masked_local =
          if String.length(local) > 2 do
            String.slice(local, 0..1) <> "***"
          else
            "***"
          end

        "#{masked_local}@#{domain}"

      _ ->
        "***"
    end
  end
end
