defmodule TamanduaServer.Alerts.Notifier.SMS do
  @moduledoc """
  SMS notification delivery via Twilio.

  Sends concise alert notifications via SMS for high-priority alerts.
  Messages are kept under 160 characters when possible.
  """

  require Logger

  @doc """
  Send an alert notification via SMS.

  ## Examples

      iex> send_alert_sms(alert, ["+15551234567"])
      {:ok, [%{sid: "SM...", to: "+15551234567"}]}
  """
  def send_alert_sms(alert, phone_numbers) when is_list(phone_numbers) do
    if twilio_configured?() do
      message = format_sms_message(alert)

      results = Enum.map(phone_numbers, fn phone ->
        send_sms(phone, message)
      end)

      errors = Enum.count(results, &match?({:error, _}, &1))
      success = length(results) - errors

      Logger.info("[SMS] Sent alert #{alert.id} to #{success}/#{length(phone_numbers)} recipient(s)")

      if errors == 0 do
        {:ok, results}
      else
        {:error, {:partial_failure, results}}
      end
    else
      Logger.warning("[SMS] Twilio not configured, skipping SMS notification")
      {:error, :not_configured}
    end
  end

  @doc """
  Send a digest SMS notification.
  """
  def send_digest_sms(alerts, phone_numbers) when is_list(alerts) and is_list(phone_numbers) do
    if twilio_configured?() do
      message = format_digest_message(alerts)

      results = Enum.map(phone_numbers, fn phone ->
        send_sms(phone, message)
      end)

      {:ok, results}
    else
      {:error, :not_configured}
    end
  end

  @doc """
  Send a test SMS to verify Twilio configuration.
  """
  def send_test_sms(phone_number) do
    message = "[Tamandua EDR] Test notification - your SMS alerts are configured correctly."
    send_sms(phone_number, message)
  end

  # ===========================================================================
  # Private Helpers
  # ===========================================================================

  defp send_sms(to_phone, message) do
    try do
      account_sid = Application.get_env(:tamandua_server, :twilio_account_sid)
      auth_token = Application.get_env(:tamandua_server, :twilio_auth_token)
      from_phone = Application.get_env(:tamandua_server, :twilio_phone_number)

      if is_nil(account_sid) or is_nil(auth_token) or is_nil(from_phone) do
        {:error, :missing_credentials}
      else
        url = "https://api.twilio.com/2010-04-01/Accounts/#{account_sid}/Messages.json"

        body = URI.encode_query(%{
          "To" => to_phone,
          "From" => from_phone,
          "Body" => message
        })

        headers = [
          {"Authorization", "Basic #{Base.encode64("#{account_sid}:#{auth_token}")}"},
          {"Content-Type", "application/x-www-form-urlencoded"}
        ]

        case HTTPoison.post(url, body, headers) do
          {:ok, %{status_code: 201, body: response_body}} ->
            response = Jason.decode!(response_body)
            Logger.debug("[SMS] Sent to #{to_phone}, SID: #{response["sid"]}")
            {:ok, %{sid: response["sid"], to: to_phone}}

          {:ok, %{status_code: status, body: body}} ->
            Logger.error("[SMS] Twilio API error #{status}: #{body}")
            {:error, {:twilio_error, status, body}}

          {:error, reason} ->
            Logger.error("[SMS] HTTP request failed: #{inspect(reason)}")
            {:error, {:http_error, reason}}
        end
      end
    rescue
      e ->
        Logger.error("[SMS] Exception sending SMS: #{inspect(e)}")
        {:error, {:exception, e}}
    end
  end

  defp format_sms_message(alert) do
    # Keep it concise for SMS
    severity = String.upcase(to_string(alert.severity))
    title = String.slice(alert.title, 0, 80)
    agent = String.slice(to_string(alert.agent_id), 0, 8)
    url = short_alert_url(alert)

    """
    [Tamandua] #{severity} Alert
    #{title}
    Agent: #{agent}
    #{url}
    """
    |> String.trim()
  end

  defp format_digest_message(alerts) do
    total = length(alerts)
    critical = Enum.count(alerts, &(&1.severity == "critical"))
    high = Enum.count(alerts, &(&1.severity == "high"))

    summary = cond do
      critical > 0 -> "#{critical} CRITICAL, #{high} HIGH"
      high > 0 -> "#{high} HIGH"
      true -> "#{total} alerts"
    end

    """
    [Tamandua] Alert Digest
    #{summary}
    Total: #{total} alerts
    View: #{dashboard_short_url()}
    """
    |> String.trim()
  end

  defp short_alert_url(alert) do
    # Use a URL shortener or just the base URL with alert ID
    base = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base}/a/#{String.slice(alert.id, 0, 8)}"
  end

  defp dashboard_short_url do
    base = Application.get_env(:tamandua_server, :base_url, "http://localhost:4000")
    "#{base}/alerts"
  end

  defp twilio_configured? do
    sid = Application.get_env(:tamandua_server, :twilio_account_sid)
    token = Application.get_env(:tamandua_server, :twilio_auth_token)
    phone = Application.get_env(:tamandua_server, :twilio_phone_number)

    not is_nil(sid) and not is_nil(token) and not is_nil(phone)
  end
end
