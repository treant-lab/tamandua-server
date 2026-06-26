defmodule TamanduaServerWeb.API.V1.SettingsControllerMobileTest do
  use TamanduaServerWeb.ConnCase, async: false

  alias TamanduaServer.Settings

  setup %{conn: conn} do
    Settings.reset(:notifications)

    user = insert!(:user, %{role: "analyst"})
    {:ok, token, _claims} = TamanduaServer.Guardian.encode_and_sign(user)

    %{conn: put_req_header(conn, "authorization", "Bearer #{token}")}
  end

  describe "POST /api/v1/settings/notifications mobile push token" do
    test "registers Expo push token with device metadata", %{conn: conn} do
      conn =
        post(conn, "/api/v1/settings/notifications", %{
          "push_token" => "ExponentPushToken[test-token]",
          "device_info" => %{
            "device_id" => "android-build-1",
            "device_name" => "Pixel",
            "platform" => "android"
          }
        })

      body = json_response(conn, 200)
      assert body["success"] == true
      assert body["data"]["pushEnabled"] == true
      assert body["data"]["pushTokenCount"] == 1

      [token] = Settings.get(:notifications, :push_tokens)
      assert token.token == "ExponentPushToken[test-token]"
      assert token.platform == "android"
      assert token.device_info["device_id"] == "android-build-1"
    end

    test "unregisters Expo push token when disabled", %{conn: conn} do
      Settings.update(:notifications, %{
        push_tokens: [
          %{
            "token" => "ExponentPushToken[test-token]",
            "device_info" => %{"platform" => "android"},
            "platform" => "android",
            "registered_at" => "2026-06-26T00:00:00Z"
          }
        ]
      })

      conn =
        post(conn, "/api/v1/settings/notifications", %{
          "push_token" => "ExponentPushToken[test-token]",
          "enabled" => false
        })

      body = json_response(conn, 200)
      assert body["data"]["pushEnabled"] == false
      assert body["data"]["pushTokenCount"] == 0
      assert Settings.get(:notifications, :push_tokens) == []
    end

    test "rejects malformed push token", %{conn: conn} do
      conn = post(conn, "/api/v1/settings/notifications", %{"push_token" => ""})

      assert %{"success" => false, "error" => "push_token cannot be empty"} =
               json_response(conn, 422)
    end
  end
end
