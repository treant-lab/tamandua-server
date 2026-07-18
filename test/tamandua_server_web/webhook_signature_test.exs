defmodule TamanduaServerWeb.WebhookSignatureTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test
  import Phoenix.ConnTest, only: [post: 3]

  alias TamanduaServerWeb.WebhookSignature

  @endpoint TamanduaServerWeb.Endpoint
  @secret "test-public-webhook-secret"

  setup do
    previous = Application.get_env(:tamandua_server, :public_webhook_secrets)

    on_exit(fn ->
      if previous do
        Application.put_env(:tamandua_server, :public_webhook_secrets, previous)
      else
        Application.delete_env(:tamandua_server, :public_webhook_secrets)
      end
    end)

    :ok
  end

  test "fails closed when a provider secret is not configured" do
    Application.delete_env(:tamandua_server, :public_webhook_secrets)
    conn = signed_conn("{}", "sha256=invalid")

    assert WebhookSignature.verify(conn, :threat_intel, "misp") ==
             {:error, :no_signing_secret}
  end

  test "verifies generic HMAC over the exact raw body" do
    configure_secret(:threat_intel, "misp")
    body = ~s({"type":"indicator","value":"example.org"})
    conn = signed_conn(body, "sha256=#{hex_hmac(body)}")

    assert WebhookSignature.verify(conn, :threat_intel, "misp") == :ok

    tampered = assign(conn, :raw_body, body <> " ")

    assert WebhookSignature.verify(tampered, :threat_intel, "misp") ==
             {:error, :invalid_signature}
  end

  test "public webhook route fails closed without a configured secret" do
    Application.delete_env(:tamandua_server, :public_webhook_secrets)

    response =
      conn(:post, "/")
      |> put_req_header("content-type", "application/json")
      |> post("/webhooks/threat-intel/misp", ~s({"type":"indicator"}))

    assert response.status == 401
    assert Jason.decode!(response.resp_body) == %{"error" => "Webhook authentication failed"}
  end

  test "router preserves the exact JSON body used by signature verification" do
    configure_secret(:threat_intel, "unknown")
    body = ~s({"value":"spacing-is-significant", "enabled":true})

    response =
      conn(:post, "/")
      |> put_req_header("content-type", "application/json")
      |> put_req_header("x-tamandua-signature", "sha256=#{hex_hmac(body)}")
      |> post("/webhooks/threat-intel/unknown", body)

    # Authentication passed; the controller rejects only the unknown provider.
    assert response.status == 400
    assert Jason.decode!(response.resp_body)["error"] == "Unknown provider: unknown"
  end

  test "reassembles cached raw-body chunks in their original order" do
    configure_secret(:alerts, "pagerduty")
    body = ~s({"event":"resolved"})
    <<first::binary-size(8), second::binary>> = body

    conn =
      conn(:post, "/")
      |> assign(:raw_body, [second, first])
      |> put_req_header("x-webhook-signature", hex_hmac(body))

    assert WebhookSignature.verify(conn, :alerts, "pagerduty") == :ok
  end

  test "verifies W&B X-Wandb-Signature as hex HMAC-SHA256" do
    configure_secret(:registries, "wandb")
    body = ~s({"event_type":"artifact_created"})

    conn =
      conn(:post, "/")
      |> assign(:raw_body, body)
      |> put_req_header("x-wandb-signature", hex_hmac(body))

    assert WebhookSignature.verify(conn, :registries, "wandb") == :ok
  end

  test "verifies Hugging Face shared secret without trusting the payload" do
    configure_secret(:registries, "huggingface")

    conn =
      conn(:post, "/")
      |> assign(:raw_body, ~s({"secret":"attacker-controlled"}))
      |> put_req_header("x-webhook-secret", @secret)

    assert WebhookSignature.verify(conn, :registries, "huggingface") == :ok

    invalid = put_req_header(conn, "x-webhook-secret", "wrong-secret")

    assert WebhookSignature.verify(invalid, :registries, "huggingface") ==
             {:error, :invalid_signature}
  end

  test "verifies MLflow v1 signature and rejects stale timestamps" do
    configure_secret(:registries, "mlflow")
    body = ~s({"event":"MODEL_VERSION_CREATED"})
    delivery_id = "delivery-123"
    timestamp = Integer.to_string(System.system_time(:second))

    conn = mlflow_conn(body, delivery_id, timestamp)
    assert WebhookSignature.verify(conn, :registries, "mlflow") == :ok

    stale_timestamp = Integer.to_string(System.system_time(:second) - 301)
    stale = mlflow_conn(body, delivery_id, stale_timestamp)

    assert WebhookSignature.verify(stale, :registries, "mlflow") ==
             {:error, :invalid_signature}
  end

  defp configure_secret(family, provider) do
    Application.put_env(:tamandua_server, :public_webhook_secrets, %{
      to_string(family) => %{provider => @secret}
    })
  end

  defp signed_conn(body, signature) do
    conn(:post, "/")
    |> assign(:raw_body, body)
    |> put_req_header("x-webhook-signature", signature)
  end

  defp mlflow_conn(body, delivery_id, timestamp) do
    message = Enum.join([delivery_id, timestamp, body], ".")
    signature = :crypto.mac(:hmac, :sha256, @secret, message) |> Base.encode64()

    conn(:post, "/")
    |> assign(:raw_body, body)
    |> put_req_header("x-mlflow-signature", "v1,#{signature}")
    |> put_req_header("x-mlflow-delivery-id", delivery_id)
    |> put_req_header("x-mlflow-timestamp", timestamp)
  end

  defp hex_hmac(body) do
    :crypto.mac(:hmac, :sha256, @secret, body)
    |> Base.encode16(case: :lower)
  end
end
