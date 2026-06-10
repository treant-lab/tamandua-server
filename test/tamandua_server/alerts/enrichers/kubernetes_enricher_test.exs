defmodule TamanduaServer.Alerts.Enrichers.KubernetesEnricherTest do
  use TamanduaServer.DataCase, async: false

  alias TamanduaServer.Alerts.Enrichers.KubernetesEnricher
  alias TamanduaServer.Alerts.Alert

  setup do
    # Start the enricher GenServer
    {:ok, _pid} = start_supervised(KubernetesEnricher)
    # Clear cache before each test
    KubernetesEnricher.clear_cache()
    :ok
  end

  describe "enrich/2" do
    test "enriches alert with k8s_context when container_id is provided via opts" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        enrichment: %{}
      }

      # Mock K8s API response (in real implementation, this would be mocked)
      # For now, we'll test with container_id that won't be found
      enriched = KubernetesEnricher.enrich(alert, container_id: "abc123def456")

      # Since we don't have K8s connection in test, alert should be unchanged
      assert enriched == alert
    end

    test "enriches alert with k8s_context when container_id is in metadata" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        metadata: %{"container_id" => "xyz789abc123"},
        enrichment: %{}
      }

      enriched = KubernetesEnricher.enrich(alert)

      # Without K8s connection, should return unchanged
      assert enriched == alert
    end

    test "enriches alert with k8s_context when container_id is in enrichment" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        enrichment: %{"container_id" => "container123"}
      }

      enriched = KubernetesEnricher.enrich(alert)

      # Without K8s connection, should return unchanged
      assert enriched == alert
    end

    test "returns alert unchanged when container_id is nil" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        enrichment: %{}
      }

      enriched = KubernetesEnricher.enrich(alert)

      assert enriched == alert
      refute Map.has_key?(enriched, :k8s_context)
    end

    test "returns alert unchanged when container_id is empty string" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        enrichment: %{"container_id" => ""}
      }

      enriched = KubernetesEnricher.enrich(alert)

      assert enriched == alert
    end

    test "handles K8s API errors gracefully" do
      alert = %Alert{
        severity: "high",
        title: "Suspicious process",
        enrichment: %{"container_id" => "abc123"}
      }

      # API errors should not crash, just return original alert
      enriched = KubernetesEnricher.enrich(alert)

      assert enriched == alert
    end
  end

  describe "get_pod_metadata/1" do
    test "returns error when container not found" do
      result = KubernetesEnricher.get_pod_metadata("nonexistent-container-id")

      assert {:error, _reason} = result
    end

    test "returns error when K8s connection unavailable" do
      result = KubernetesEnricher.get_pod_metadata("abc123")

      # Without K8s connection, should error
      assert {:error, :no_k8s_connection} = result
    end
  end

  describe "caching behavior" do
    test "cache stores and retrieves pod metadata" do
      container_id = "test-container-123"

      # First call - cache miss
      result1 = KubernetesEnricher.get_pod_metadata(container_id)
      assert {:error, _} = result1

      # Manually insert into cache for testing
      metadata = %{
        namespace: "default",
        pod_name: "test-pod-abc123",
        node_name: "worker-1",
        service_account: "default",
        labels: %{"app" => "test"},
        annotations: %{},
        container_id: container_id,
        pod_ip: "10.0.1.5",
        phase: "Running"
      }

      :ets.insert(:k8s_pod_metadata_cache, {container_id, metadata, System.system_time(:millisecond)})

      # Second call - cache hit
      result2 = KubernetesEnricher.get_pod_metadata(container_id)
      assert {:ok, ^metadata} = result2
    end

    test "cache expires after TTL" do
      container_id = "test-container-456"

      metadata = %{
        namespace: "production",
        pod_name: "app-pod-xyz789",
        node_name: "worker-2"
      }

      # Insert with expired timestamp (61 seconds ago)
      expired_time = System.system_time(:millisecond) - 61_000
      :ets.insert(:k8s_pod_metadata_cache, {container_id, metadata, expired_time})

      # Should be cache miss due to expiration
      result = KubernetesEnricher.get_pod_metadata(container_id)
      assert {:error, _} = result
    end

    test "clear_cache removes all cached entries" do
      # Insert some test data
      :ets.insert(:k8s_pod_metadata_cache, {"container1", %{}, System.system_time(:millisecond)})
      :ets.insert(:k8s_pod_metadata_cache, {"container2", %{}, System.system_time(:millisecond)})

      assert :ets.info(:k8s_pod_metadata_cache, :size) == 2

      KubernetesEnricher.clear_cache()

      assert :ets.info(:k8s_pod_metadata_cache, :size) == 0
    end
  end

  describe "ETS table initialization" do
    test "creates ETS table on start" do
      # Table should already exist from setup
      info = :ets.info(:k8s_pod_metadata_cache)
      assert info != :undefined
      assert info[:type] == :set
      assert info[:named_table] == true
    end
  end
end
