defmodule TamanduaServer.Webhooks.RetryHandlerTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Webhooks.{RetryHandler, Webhook}

  describe "calculate_retry_delay/3" do
    setup do
      webhook = %Webhook{
        backoff_strategy: "exponential",
        max_retries: 3
      }

      {:ok, webhook: webhook}
    end

    test "calculates exponential backoff", %{webhook: webhook} do
      delay1 = RetryHandler.calculate_retry_delay(webhook, 1)
      delay2 = RetryHandler.calculate_retry_delay(webhook, 2)
      delay3 = RetryHandler.calculate_retry_delay(webhook, 3)

      # Exponential backoff should increase
      assert delay2 > delay1
      assert delay3 > delay2
    end

    test "calculates linear backoff" do
      webhook = %Webhook{backoff_strategy: "linear", max_retries: 3}

      delay1 = RetryHandler.calculate_retry_delay(webhook, 1)
      delay2 = RetryHandler.calculate_retry_delay(webhook, 2)

      # Linear backoff should increase linearly
      assert delay2 > delay1
    end

    test "adjusts delay based on error status code", %{webhook: webhook} do
      # Rate limit error should have longer delay
      delay_rate_limit = RetryHandler.calculate_retry_delay(webhook, 1, %{status: 429})

      # Client error should have shorter delay
      delay_client = RetryHandler.calculate_retry_delay(webhook, 1, %{status: 400})

      assert delay_rate_limit > delay_client
    end

    test "caps maximum delay at 1 hour", %{webhook: webhook} do
      # Very high retry count
      delay = RetryHandler.calculate_retry_delay(webhook, 20)

      # Should be capped
      assert delay <= 3600
    end
  end

  describe "should_retry?/3" do
    setup do
      webhook = %Webhook{
        id: Ecto.UUID.generate(),
        max_retries: 3,
        health_status: "healthy"
      }

      {:ok, webhook: webhook}
    end

    test "returns false when max retries reached", %{webhook: webhook} do
      refute RetryHandler.should_retry?(webhook, 3, %{})
    end

    test "returns false for permanent errors", %{webhook: webhook} do
      refute RetryHandler.should_retry?(webhook, 1, %{status: 404})
      refute RetryHandler.should_retry?(webhook, 1, %{status: 401})
    end

    test "returns true for retryable errors", %{webhook: webhook} do
      assert RetryHandler.should_retry?(webhook, 1, %{status: 500})
      assert RetryHandler.should_retry?(webhook, 1, %{status: 503})
    end
  end

  describe "is_permanent_error?/1" do
    test "identifies permanent HTTP errors" do
      assert RetryHandler.is_permanent_error?(%{status: 401})
      assert RetryHandler.is_permanent_error?(%{status: 403})
      assert RetryHandler.is_permanent_error?(%{status: 404})
      assert RetryHandler.is_permanent_error?(%{status: 410})
    end

    test "identifies retryable HTTP errors" do
      refute RetryHandler.is_permanent_error?(%{status: 500})
      refute RetryHandler.is_permanent_error?(%{status: 503})
      refute RetryHandler.is_permanent_error?(%{status: 429})
    end

    test "identifies permanent network errors" do
      assert RetryHandler.is_permanent_error?(%{message: "DNS resolution failed: nxdomain"})
      assert RetryHandler.is_permanent_error?(%{message: "SSL certificate verify failed"})
    end

    test "identifies retryable network errors" do
      refute RetryHandler.is_permanent_error?(%{message: "Connection timeout"})
      refute RetryHandler.is_permanent_error?(%{message: "Network unreachable"})
    end
  end

  describe "get_retry_stats/1" do
    test "returns retry statistics for webhook" do
      webhook_id = Ecto.UUID.generate()

      stats = RetryHandler.get_retry_stats(webhook_id)

      assert is_map(stats)
      assert Map.has_key?(stats, :total_deliveries)
      assert Map.has_key?(stats, :total_retries)
      assert Map.has_key?(stats, :failure_rate)
    end
  end
end
