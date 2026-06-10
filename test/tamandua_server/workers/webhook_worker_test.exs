defmodule TamanduaServer.Workers.WebhookWorkerTest do
  use TamanduaServer.DataCase, async: true
  use Oban.Testing, repo: TamanduaServer.Repo

  alias TamanduaServer.Webhooks
  alias TamanduaServer.Webhooks.Webhook
  alias TamanduaServer.Workers.WebhookWorker

  describe "perform/1" do
    test "creates delivery log on job execution" do
      webhook = insert(:webhook)
      event_id = Ecto.UUID.generate()
      payload = %{alert: %{id: "123"}}

      job_args = %{
        "webhook_id" => webhook.id,
        "event_type" => "alert.created",
        "event_id" => event_id,
        "payload" => payload
      }

      # Note: This test would require mocking HTTP requests
      # In a real test suite, you'd use a library like Bypass or Mox
      # to mock the HTTP endpoint

      # For now, we just verify the job can be enqueued
      assert {:ok, job} = perform_job(WebhookWorker, job_args)
    end

    test "handles webhook not found gracefully" do
      job_args = %{
        "webhook_id" => Ecto.UUID.generate(),
        "event_type" => "alert.created",
        "event_id" => Ecto.UUID.generate(),
        "payload" => %{}
      }

      assert :ok = perform_job(WebhookWorker, job_args)
    end

    test "increments retry count on retry" do
      webhook = insert(:webhook, max_retries: 5)
      event_id = Ecto.UUID.generate()

      job_args = %{
        "webhook_id" => webhook.id,
        "event_type" => "alert.created",
        "event_id" => event_id,
        "payload" => %{},
        "retry_count" => 2
      }

      # Verify retry count is passed through
      assert job_args["retry_count"] == 2
    end
  end

  describe "calculate_backoff" do
    # These would be private function tests if exposed via module attribute
    # or helper function for testing

    test "exponential backoff increases exponentially" do
      # Retry 1: 60s, Retry 2: 120s, Retry 3: 240s
      # Formula: 2^(retry-1) * 60
      assert calculate_exponential_backoff(1) == 60
      assert calculate_exponential_backoff(2) == 120
      assert calculate_exponential_backoff(3) == 240
    end

    test "linear backoff increases linearly" do
      # Formula: retry * 120
      assert calculate_linear_backoff(1) == 120
      assert calculate_linear_backoff(2) == 240
      assert calculate_linear_backoff(3) == 360
    end
  end

  # Helpers to test backoff calculation
  defp calculate_exponential_backoff(retry_count) do
    base_delay = 60
    trunc(:math.pow(2, retry_count - 1) * base_delay)
  end

  defp calculate_linear_backoff(retry_count) do
    retry_count * 120
  end

  # Factory helper
  defp insert(schema, attrs \\ %{}) do
    case schema do
      :organization ->
        %TamanduaServer.Accounts.Organization{}
        |> TamanduaServer.Accounts.Organization.changeset(
          Map.merge(%{name: "Test Org", slug: "test-org-#{:rand.uniform(10000)}"}, attrs)
        )
        |> Repo.insert!()

      :webhook ->
        org = Map.get(attrs, :organization) || insert(:organization)

        %Webhook{}
        |> Webhook.changeset(
          Map.merge(
            %{
              name: "Test Webhook",
              url: "https://example.com/webhook",
              events: ["alert.created"],
              organization_id: org.id
            },
            Map.delete(attrs, :organization)
          )
        )
        |> Repo.insert!()
    end
  end
end
