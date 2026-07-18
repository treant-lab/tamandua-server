defmodule TamanduaServer.NotificationCenter.Channels.SmsWorker do
  @moduledoc """
  Oban worker for sending SMS notifications via Twilio.
  """
  use Oban.Worker,
    queue: :notifications,
    max_attempts: 3

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.NotificationCenter.{NotificationDelivery}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"delivery_id" => delivery_id}}) do
    delivery = Repo.get!(NotificationDelivery, delivery_id) |> Repo.preload(:notification)
    notification = Repo.preload(delivery.notification, :user)

    # Check if user has phone number
    case notification.user do
      %{phone: phone} when not is_nil(phone) ->
        send_sms(delivery, notification, phone)

      _ ->
        delivery
        |> NotificationDelivery.failed_changeset("User has no phone number")
        |> Repo.update()

        {:error, "No phone number"}
    end
  end

  defp send_sms(delivery, notification, phone) do
    # Build SMS body (max 160 chars for standard SMS)
    body = build_sms_body(notification)

    case twilio_send_sms(phone, body) do
      {:ok, response} ->
        delivery
        |> NotificationDelivery.sent_changeset(response)
        |> Repo.update()

        Logger.info("[SmsWorker] SMS sent to #{phone}")
        :ok

      {:error, reason} ->
        delivery
        |> NotificationDelivery.failed_changeset(reason)
        |> Repo.update()

        Logger.error("[SmsWorker] Failed to send SMS: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp build_sms_body(notification) do
    # Truncate to 160 chars
    text = "[Tamandua] #{notification.title}"

    if String.length(text) > 160 do
      String.slice(text, 0, 157) <> "..."
    else
      text
    end
  end

  defp twilio_send_sms(to, body) do
    account_sid = Application.get_env(:tamandua_server, :twilio_account_sid)
    auth_token = Application.get_env(:tamandua_server, :twilio_auth_token)
    from_number = Application.get_env(:tamandua_server, :twilio_from_number)

    if is_nil(account_sid) or is_nil(auth_token) or is_nil(from_number) do
      {:error, "Twilio not configured"}
    else
      url = "https://api.twilio.com/2010-04-01/Accounts/#{account_sid}/Messages.json"

      headers = [
        {"Authorization", "Basic #{Base.encode64("#{account_sid}:#{auth_token}")}"},
        {"Content-Type", "application/x-www-form-urlencoded"}
      ]

      body_params =
        URI.encode_query(%{
          "From" => from_number,
          "To" => to,
          "Body" => body
        })

      case HTTPoison.post(url, body_params, headers) do
        {:ok, %{status_code: code, body: response_body}} when code in 200..299 ->
          {:ok, %{status_code: code, body: response_body}}

        {:ok, %{status_code: code, body: response_body}} ->
          {:error, "HTTP #{code}: #{response_body}"}

        {:error, %{reason: reason}} ->
          {:error, reason}
      end
    end
  end
end
