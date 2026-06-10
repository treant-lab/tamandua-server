defmodule TamanduaServer.Auth.MFA.SMS do
  @moduledoc """
  SMS provider for MFA using Twilio.
  """

  require Logger

  @code_length 6
  @code_ttl 300  # 5 minutes in seconds
  @rate_limit_window 60  # 1 minute
  @rate_limit_max 3  # Max 3 SMS per minute per phone number

  @doc """
  Generate a random 6-digit SMS code.
  """
  def generate_code do
    :rand.uniform(999999)
    |> Integer.to_string()
    |> String.pad_leading(@code_length, "0")
  end

  @doc """
  Send an SMS code to a phone number.
  Returns {:ok, code} on success, {:error, reason} on failure.
  """
  def send_code(phone_number) do
    with :ok <- check_rate_limit(phone_number),
         code <- generate_code(),
         :ok <- deliver_sms(phone_number, code) do
      record_send(phone_number)
      {:ok, code}
    else
      {:error, :rate_limited} = error ->
        Logger.warning("SMS rate limit exceeded for #{mask_phone(phone_number)}")
        error

      {:error, reason} = error ->
        Logger.error("Failed to send SMS to #{mask_phone(phone_number)}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Verify an SMS code.
  """
  def verify(stored_code, stored_code_sent_at, provided_code) do
    with true <- code_not_expired?(stored_code_sent_at),
         true <- codes_match?(stored_code, provided_code) do
      true
    else
      _ -> false
    end
  end

  # Deliver SMS via Twilio (or mock in dev/test)
  defp deliver_sms(phone_number, code) do
    if Application.get_env(:tamandua_server, :mock_sms, false) do
      # Mock mode for development
      Logger.info("MOCK SMS to #{phone_number}: Your Tamandua verification code is #{code}")
      :ok
    else
      # Real Twilio integration
      send_twilio_sms(phone_number, code)
    end
  end

  defp send_twilio_sms(phone_number, code) do
    # Get Twilio credentials from config
    config = Application.get_env(:tamandua_server, :twilio, [])
    account_sid = Keyword.get(config, :account_sid)
    auth_token = Keyword.get(config, :auth_token)
    from_number = Keyword.get(config, :from_number)

    if account_sid && auth_token && from_number do
      # Twilio API call
      url = "https://api.twilio.com/2010-04-01/Accounts/#{account_sid}/Messages.json"
      auth = "#{account_sid}:#{auth_token}" |> Base.encode64()

      body =
        URI.encode_query(%{
          "To" => phone_number,
          "From" => from_number,
          "Body" => "Your Tamandua verification code is #{code}. Valid for 5 minutes."
        })

      headers = [
        {"Authorization", "Basic #{auth}"},
        {"Content-Type", "application/x-www-form-urlencoded"}
      ]

      case Req.post(url, body: body, headers: headers) do
        {:ok, %{status: 201}} ->
          :ok

        {:ok, %{status: status, body: body}} ->
          {:error, "Twilio API returned status #{status}: #{inspect(body)}"}

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :twilio_not_configured}
    end
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
    # Hash stored code for comparison
    stored_hash = hash_code(stored)
    Bcrypt.verify_pass(provided, stored_hash)
  end

  @doc """
  Hash an SMS code for storage.
  """
  def hash_code(code) do
    Bcrypt.hash_pwd_salt(code)
  end

  # Rate limiting using ETS
  @rate_limit_table :sms_rate_limits

  defp ensure_rate_limit_table do
    case :ets.whereis(@rate_limit_table) do
      :undefined ->
        :ets.new(@rate_limit_table, [:set, :public, :named_table])

      _ ->
        :ok
    end
  end

  defp check_rate_limit(phone_number) do
    ensure_rate_limit_table()
    now = System.system_time(:second)
    key = hash_phone(phone_number)

    case :ets.lookup(@rate_limit_table, key) do
      [{^key, count, window_start}] ->
        if now - window_start > @rate_limit_window do
          # Window expired
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

  defp record_send(phone_number) do
    ensure_rate_limit_table()
    now = System.system_time(:second)
    key = hash_phone(phone_number)

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

  defp hash_phone(phone_number) do
    :crypto.hash(:sha256, phone_number) |> Base.encode16()
  end

  defp mask_phone(phone_number) do
    if String.length(phone_number) > 4 do
      last_4 = String.slice(phone_number, -4, 4)
      "***-***-#{last_4}"
    else
      "***"
    end
  end
end
