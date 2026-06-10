defmodule TamanduaServer.AISecurity.AIGatewayTest do
  use ExUnit.Case, async: false

  alias TamanduaServer.AISecurity.AIGateway

  setup do
    case Process.whereis(AIGateway) do
      nil ->
        {:ok, _pid} = AIGateway.start_link([])

      _pid ->
        :ets.delete_all_objects(:ai_gateway_events)
        :ets.delete_all_objects(:ai_gateway_stats)
        :ets.insert(:ai_gateway_stats, {:counters, %{total_ingested: 0, rejected_sensitive: 0}})
    end

    {:ok, _policy} =
      AIGateway.update_policy(%{
        "policy_id" => "default-metadata-only",
        "default_decision" => "monitor",
        "enforce_block" => false,
        "allowlist_providers" => [],
        "blocklist_providers" => [],
        "allowlist_domains" => [],
        "blocklist_domains" => [],
        "blocked_data_categories" => ["credentials", "secrets"],
        "high_risk_data_categories" => ["pii", "source_code", "customer_data", "financial_data"],
        "max_risk_score_allow" => 25,
        "max_risk_score_monitor" => 70
      })

    :ok
  end

  test "ingests metadata-only events and infers provider from domain" do
    {:ok, event} =
      AIGateway.ingest_event(%{
        "domain" => "https://api.openai.com/v1/chat/completions",
        "model" => "gpt-4o-mini",
        "user_id" => "user-1",
        "request_count" => "3",
        "input_tokens" => "100",
        "output_tokens" => 25
      })

    assert event.provider == "openai"
    assert event.model == "gpt-4o-mini"
    assert event.user_id == "user-1"
    assert event.request_count == 3
    assert event.input_tokens == 100
    assert event.output_tokens == 25
    assert event.policy_decision == "monitor"
    assert event.policy_reasons == ["default_policy"]
  end

  test "rejects prompt, response, body, and credential fields" do
    assert {:error, {:sensitive_fields, fields}} =
             AIGateway.ingest_event(%{
               "provider" => "openai",
               "prompt" => "secret prompt",
               "headers" => %{"authorization" => "Bearer token"}
             })

    assert "prompt" in fields
    assert "headers" in fields
    assert "authorization" in fields
  end

  test "evaluates policy decisions without storing prompts" do
    {:ok, policy} =
      AIGateway.update_policy(%{
        "blocklist_providers" => ["openai"],
        "enforce_block" => true
      })

    assert policy.enforce_block == true

    {:ok, decision} =
      AIGateway.evaluate_event(%{
        "provider" => "openai",
        "domain" => "api.openai.com",
        "risk_score" => 10
      })

    assert decision.policy_decision == "block"
    assert decision.policy_reasons == ["blocked_provider"]
    assert decision.policy_enforced == true
    assert decision.content_inspection == false
    assert decision.prompt_capture == false
  end

  test "batch ingest accepts clean metadata and rejects sensitive records" do
    {:ok, result} =
      AIGateway.ingest_batch([
        %{"provider" => "anthropic", "domain" => "claude.ai"},
        %{"provider" => "openai", "messages" => [%{"role" => "user", "content" => "x"}]}
      ])

    assert result.accepted_count == 1
    assert result.rejected_count == 1
    assert hd(result.accepted).provider == "anthropic"
    assert hd(result.rejected).reason == "sensitive_fields"
  end

  test "health reports gateway capabilities separately from inline enforcement" do
    {:ok, _event} =
      AIGateway.ingest_event(%{"provider" => "openrouter", "domain" => "openrouter.ai"})

    health = AIGateway.health()

    assert health.status == "active"
    assert health.event_count >= 1
    assert health.collection_mode == "gateway_metadata"
    assert health.content_inspection == false
    assert health.prompt_capture == false
    assert health.inline_proxy == false
    assert health.enforcement.available == true
    assert health.enforcement.mode == "endpoint_action_bridge"
    assert health.persistence.status in ["available", "partial", "unconfigured", "unavailable"]
  end

  test "keeps safe nested metadata but rejects sensitive nested metadata" do
    assert {:ok, event} =
             AIGateway.ingest_event(%{
               source: "endpoint_telemetry",
               provider: "openai",
               domain: "chatgpt.com",
               access_method: "endpoint_dns",
               metadata: %{
                 source_event_type: "dns_query",
                 ai_signal: "domain",
                 prompt_capture: false
               }
             })

    assert event.metadata["source_event_type"] == "dns_query"
    assert event.metadata["ai_signal"] == "domain"
    assert event.metadata["prompt_capture"] == false

    assert {:error, {:sensitive_fields, ["prompt"]}} =
             AIGateway.ingest_event(%{
               source: "endpoint_telemetry",
               provider: "openai",
               domain: "chatgpt.com",
               metadata: %{prompt: "do not store me"}
             })
  end

  test "preserves browser guard metadata without accepting content" do
    assert {:ok, event} =
             AIGateway.ingest_event(%{
               "source" => "browser_extension",
               "source_event_type" => "browser.upload_attempt",
               "domain" => "chatgpt.com",
               "provider" => "openai",
               "access_method" => "browser",
               "file_count" => 2,
               "filename_extension" => "ts",
               "data_categories" => ["source_code", "credentials"],
               "classifier_counts" => %{"credentials" => 1},
               "extension_id" => "abcdefghijklmnop",
               "schema_version" => 1,
               "extension_version" => "0.1.0",
               "policy_mode" => "block",
               "policy_source" => "managed",
               "policy_version" => "2026-05-24.1",
               "queue_length" => 3,
               "dynamic_rule_count" => 1,
               "mitre_techniques" => ["T1566", "T1555.003"],
               "mitre_tactics" => ["Initial Access", "Credential Access"],
               "attack_mappings" => [
                 %{"tactic" => "Initial Access", "technique" => "T1566", "name" => "Phishing"}
               ],
               "wallet_method" => "signTransaction",
               "content_inspection" => false,
               "prompt_capture" => false
             })

    assert event.source == "browser_extension"
    assert event.access_method == "browser"
    assert event.metadata["file_count"] == 2
    assert event.metadata["filename_extension"] == "ts"
    assert event.metadata["classifier_counts"] == %{"credentials" => 1}
    assert event.metadata["extension_id"] == "abcdefghijklmnop"
    assert event.metadata["schema_version"] == 1
    assert event.metadata["extension_version"] == "0.1.0"
    assert event.metadata["policy_mode"] == "block"
    assert event.metadata["policy_source"] == "managed"
    assert event.metadata["policy_version"] == "2026-05-24.1"
    assert event.metadata["queue_length"] == 3
    assert event.metadata["dynamic_rule_count"] == 1
    assert event.metadata["mitre_techniques"] == ["T1566", "T1555.003"]
    assert event.metadata["mitre_tactics"] == ["Initial Access", "Credential Access"]
    assert [%{"technique" => "T1566"}] = event.metadata["attack_mappings"]
    assert event.metadata["wallet_method"] == "signTransaction"
    assert event.content_inspection == false
    assert event.prompt_capture == false

    assert {:error, {:sensitive_fields, fields}} =
             AIGateway.ingest_event(%{
               "source" => "browser_extension",
               "domain" => "chatgpt.com",
               "form_value" => "safe-looking but unsupported",
               "content" => "raw prompt or form text"
             })

    assert "content" in fields
  end
end
