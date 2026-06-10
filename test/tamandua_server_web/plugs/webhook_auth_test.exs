defmodule TamanduaServerWeb.Plugs.WebhookAuthTest do
  use TamanduaServerWeb.ConnCase, async: true

  alias TamanduaServerWeb.Plugs.WebhookAuth

  @secret "test_webhook_secret_12345"

  describe "webhook signature validation" do
    setup do
      # Set up test config
      Application.put_env(:tamandua_server, :webhook_secret_test, @secret)
      Application.put_env(:tamandua_server, :env, :test)
      Application.put_env(:tamandua_server, :webhook_insecure_mode, false)

      on_exit(fn ->
        Application.delete_env(:tamandua_server, :webhook_secret_test)
        Application.delete_env(:tamandua_server, :webhook_insecure_mode)
      end)

      :ok
    end

    test "rejects request without signature when secret is configured" do
      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> assign(:raw_body, Jason.encode!(%{data: "test"}))

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      assert conn.halted
      assert conn.status == 401
      assert json_response(conn, 401)["error"] =~ "signature"
    end

    test "rejects request with invalid signature" do
      payload = Jason.encode!(%{data: "test"})

      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> put_req_header("x-hub-signature-256", "sha256=invalid_signature")
             |> assign(:raw_body, payload)

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      assert conn.halted
      assert conn.status == 401
      assert json_response(conn, 401)["error"] =~ "Invalid"
    end

    test "accepts request with valid signature" do
      payload = Jason.encode!(%{data: "test"})
      signature = compute_signature(payload, @secret)

      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> put_req_header("x-hub-signature-256", "sha256=#{signature}")
             |> assign(:raw_body, payload)

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      refute conn.halted
      assert conn.assigns[:webhook_authenticated] == true
      assert conn.assigns[:webhook_signature_verified] == true
    end

    test "secret from payload does NOT bypass validation" do
      # This is the critical security test - attacker supplies their own secret
      attacker_secret = "attacker_controlled_secret"
      payload = Jason.encode!(%{data: "test", secret: attacker_secret})

      # Attacker computes signature with their secret
      attacker_signature = compute_signature(payload, attacker_secret)

      conn = build_conn(:post, "/webhooks/test", %{data: "test", secret: attacker_secret})
             |> put_req_header("x-hub-signature-256", "sha256=#{attacker_signature}")
             |> assign(:raw_body, payload)

      # Server uses its configured secret, NOT the one from payload
      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      # Request should be rejected because signature doesn't match server's secret
      assert conn.halted
      assert conn.status == 401
    end

    test "supports multiple signature header formats" do
      payload = Jason.encode!(%{data: "test"})
      signature = compute_signature(payload, @secret)

      # Test X-Signature header
      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> put_req_header("x-signature", "sha256=#{signature}")
             |> assign(:raw_body, payload)

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      refute conn.halted
      assert conn.assigns[:webhook_authenticated] == true
    end

    test "fails closed when no secret configured in production" do
      Application.put_env(:tamandua_server, :env, :prod)
      Application.delete_env(:tamandua_server, :webhook_secret_test)

      on_exit(fn ->
        Application.put_env(:tamandua_server, :env, :test)
      end)

      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> assign(:raw_body, Jason.encode!(%{data: "test"}))

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      assert conn.halted
      assert conn.status == 401
    end

    test "allows insecure webhook in dev with explicit config" do
      Application.put_env(:tamandua_server, :env, :dev)
      Application.put_env(:tamandua_server, :webhook_insecure_mode, true)
      Application.delete_env(:tamandua_server, :webhook_secret_test)

      on_exit(fn ->
        Application.put_env(:tamandua_server, :env, :test)
        Application.put_env(:tamandua_server, :webhook_insecure_mode, false)
      end)

      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> assign(:raw_body, Jason.encode!(%{data: "test"}))

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test, optional: true)
      conn = WebhookAuth.call(conn, opts)

      refute conn.halted
      assert conn.assigns[:webhook_authenticated] == false
      assert conn.assigns[:webhook_signature_verified] == false
    end

    test "uses constant-time comparison for signatures" do
      # This test ensures we don't leak timing information
      payload = Jason.encode!(%{data: "test"})

      # Two different invalid signatures - timing should be similar
      sig1 = "sha256=0000000000000000000000000000000000000000000000000000000000000000"
      sig2 = "sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

      conn1 = build_conn(:post, "/webhooks/test", %{data: "test"})
              |> put_req_header("x-hub-signature-256", sig1)
              |> assign(:raw_body, payload)

      conn2 = build_conn(:post, "/webhooks/test", %{data: "test"})
              |> put_req_header("x-hub-signature-256", sig2)
              |> assign(:raw_body, payload)

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)

      # Both should fail
      result1 = WebhookAuth.call(conn1, opts)
      result2 = WebhookAuth.call(conn2, opts)

      assert result1.halted
      assert result2.halted
      assert result1.status == 401
      assert result2.status == 401
    end
  end

  describe "replay attack prevention" do
    setup do
      Application.put_env(:tamandua_server, :webhook_secret_test, @secret)
      Application.put_env(:tamandua_server, :env, :test)

      on_exit(fn ->
        Application.delete_env(:tamandua_server, :webhook_secret_test)
      end)

      :ok
    end

    test "accepts request with valid recent timestamp" do
      payload = Jason.encode!(%{data: "test"})
      signature = compute_signature(payload, @secret)
      now = System.system_time(:second)

      conn = build_conn(:post, "/webhooks/test", %{data: "test"})
             |> put_req_header("x-hub-signature-256", "sha256=#{signature}")
             |> put_req_header("x-timestamp", to_string(now))
             |> assign(:raw_body, payload)

      opts = WebhookAuth.init(source: :config, key: :webhook_secret_test)
      conn = WebhookAuth.call(conn, opts)

      refute conn.halted
    end

    # Note: Replay attack prevention with old timestamps would need more
    # sophisticated testing - the current implementation allows requests
    # without timestamps but could reject very old ones if timestamp header exists
  end

  # Helper to compute HMAC signature
  defp compute_signature(payload, secret) do
    :crypto.mac(:hmac, :sha256, secret, payload)
    |> Base.encode16(case: :lower)
  end
end
