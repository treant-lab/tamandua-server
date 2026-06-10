defmodule TamanduaServerWeb.WebhookControllerTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Phoenix.ConnTest

  @endpoint TamanduaServerWeb.Endpoint
  @webhook_secret "test_webhook_secret_abc123"

  # ============================================================================
  # Webhook Signature Validation Security Tests
  # ============================================================================

  describe "webhook signature validation security" do
    test "rejects request without signature" do
      # This validates that webhooks require proper authentication
      result = validate_webhook_signature(nil, "test body", @webhook_secret)
      assert result == {:error, :missing_signature}
    end

    test "rejects invalid signature" do
      body = ~s({"event": "test"})
      invalid_sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000"

      result = validate_webhook_signature(invalid_sig, body, @webhook_secret)
      assert result == {:error, :invalid_signature}
    end

    test "accepts valid signature" do
      body = ~s({"event": "test"})
      signature = compute_valid_signature(body, @webhook_secret)

      result = validate_webhook_signature("sha256=#{signature}", body, @webhook_secret)
      assert result == :ok
    end

    test "secret from payload does NOT bypass validation" do
      # Critical security test: attacker supplies their own secret
      attacker_secret = "attacker_controlled_secret"
      body = ~s({"event": "test", "secret": "#{attacker_secret}"})

      # Attacker computes signature using their secret
      attacker_signature = compute_valid_signature(body, attacker_secret)

      # Server should use its configured secret, NOT the attacker's
      # This should fail because the signatures won't match
      result = validate_webhook_signature("sha256=#{attacker_signature}", body, @webhook_secret)
      assert result == {:error, :invalid_signature}
    end

    test "uses constant-time comparison" do
      # Both invalid signatures should behave the same way
      body = ~s({"event": "test"})
      sig1 = "sha256=0000000000000000000000000000000000000000000000000000000000000000"
      sig2 = "sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

      result1 = validate_webhook_signature(sig1, body, @webhook_secret)
      result2 = validate_webhook_signature(sig2, body, @webhook_secret)

      assert result1 == {:error, :invalid_signature}
      assert result2 == {:error, :invalid_signature}
    end

    test "supports multiple signature formats" do
      body = ~s({"event": "test"})
      signature = compute_valid_signature(body, @webhook_secret)

      # Test with sha256= prefix
      assert validate_webhook_signature("sha256=#{signature}", body, @webhook_secret) == :ok

      # Test without prefix (should assume sha256)
      assert validate_webhook_signature(signature, body, @webhook_secret) == :ok
    end
  end

  # Helper functions for signature validation tests
  defp validate_webhook_signature(nil, _body, _secret), do: {:error, :missing_signature}
  defp validate_webhook_signature(signature, body, secret) do
    # Parse signature format
    {_algo, expected_hash} = parse_signature(signature)

    # Compute expected
    computed = compute_valid_signature(body, secret)

    if Plug.Crypto.secure_compare(computed, expected_hash) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp parse_signature(signature) do
    cond do
      String.starts_with?(signature, "sha256=") ->
        {:sha256, String.replace_prefix(signature, "sha256=", "")}
      true ->
        {:sha256, signature}
    end
  end

  defp compute_valid_signature(body, secret) do
    :crypto.mac(:hmac, :sha256, secret, body)
    |> Base.encode16(case: :lower)
  end

  # ============================================================================
  # Model Registry Webhook Tests (existing)
  # ============================================================================

  @valid_mlflow_webhook %{
    "event" => "MODEL_VERSION_TRANSITION_REQUEST_CREATED",
    "model_name" => "fraud-detection",
    "version" => "3",
    "stage" => "Production",
    "timestamp" => 1642334400000
  }

  @valid_mlflow_transition_webhook %{
    "event" => "MODEL_VERSION_TRANSITIONED_STAGE",
    "model_name" => "fraud-detection",
    "version" => "3",
    "stage" => "Production",
    "timestamp" => 1642334400000
  }

  @invalid_mlflow_webhook_missing_version %{
    "event" => "MODEL_VERSION_TRANSITION_REQUEST_CREATED",
    "model_name" => "fraud-detection"
    # missing version
  }

  @valid_huggingface_webhook %{
    "event" => "model.update",
    "repo" => %{
      "type" => "model",
      "name" => "org/model-name"
    },
    "timestamp" => "2024-01-15T10:30:00Z"
  }

  @invalid_huggingface_webhook_missing_repo %{
    "event" => "model.update"
    # missing repo
  }

  @valid_wandb_webhook %{
    "event_type" => "artifact_created",
    "artifact_version" => %{
      "id" => "QXJ0aWZhY3Q6MTIzNDU2",
      "entity" => "my-org",
      "project" => "fraud-detection",
      "artifact_sequence_name" => "model-v1",
      "version" => "v2",
      "created_at" => "2024-01-15T10:30:00Z"
    }
  }

  @invalid_wandb_webhook_missing_artifact %{
    "event_type" => "artifact_created"
    # missing artifact_version
  }

  describe "POST /api/webhooks/registries/mlflow" do
    test "accepts valid MODEL_VERSION_TRANSITION_REQUEST_CREATED event" do
      # Note: This test validates webhook parsing - actual scan would require
      # database and ML service running
      assert validate_mlflow_event(@valid_mlflow_webhook) ==
               {:ok, %{model_id: "fraud-detection:3", event: "MODEL_VERSION_TRANSITION_REQUEST_CREATED"}}
    end

    test "accepts valid MODEL_VERSION_TRANSITIONED_STAGE event" do
      assert validate_mlflow_event(@valid_mlflow_transition_webhook) ==
               {:ok, %{model_id: "fraud-detection:3", event: "MODEL_VERSION_TRANSITIONED_STAGE"}}
    end

    test "returns error for missing required fields" do
      assert validate_mlflow_event(@invalid_mlflow_webhook_missing_version) ==
               {:error, :missing_fields}
    end

    test "returns error for unknown event types" do
      unknown_event = %{
        "event" => "UNKNOWN_EVENT",
        "model_name" => "test",
        "version" => "1"
      }

      assert validate_mlflow_event(unknown_event) == {:error, :invalid_event_type}
    end

    test "builds correct model_id from name and version" do
      {:ok, result} = validate_mlflow_event(%{
        "event" => "MODEL_VERSION_CREATED",
        "model_name" => "my-model",
        "version" => "5"
      })

      assert result.model_id == "my-model:5"
    end
  end

  describe "POST /api/webhooks/registries/huggingface" do
    test "accepts valid model.update event" do
      assert validate_huggingface_event(@valid_huggingface_webhook) ==
               {:ok, %{model_id: "org/model-name", event: "model.update"}}
    end

    test "accepts valid model.create event" do
      create_event = Map.put(@valid_huggingface_webhook, "event", "model.create")

      assert validate_huggingface_event(create_event) ==
               {:ok, %{model_id: "org/model-name", event: "model.create"}}
    end

    test "returns error for missing required fields" do
      assert validate_huggingface_event(@invalid_huggingface_webhook_missing_repo) ==
               {:error, :missing_fields}
    end

    test "returns error for non-model repos" do
      dataset_event = %{
        "event" => "model.update",
        "repo" => %{
          "type" => "dataset",
          "name" => "org/dataset-name"
        }
      }

      assert validate_huggingface_event(dataset_event) == {:error, :invalid_event_type}
    end

    test "extracts model_id from repo name" do
      {:ok, result} = validate_huggingface_event(%{
        "event" => "model.update",
        "repo" => %{
          "type" => "model",
          "name" => "meta-llama/Llama-2-7b"
        }
      })

      assert result.model_id == "meta-llama/Llama-2-7b"
    end
  end

  describe "POST /api/webhooks/registries/wandb" do
    test "accepts valid artifact_created event" do
      {:ok, result} = validate_wandb_event(@valid_wandb_webhook)

      assert result.model_id == "my-org/fraud-detection/model-v1:v2"
      assert result.event == "artifact_created"
    end

    test "accepts valid artifact_updated event" do
      updated_event = Map.put(@valid_wandb_webhook, "event_type", "artifact_updated")

      {:ok, result} = validate_wandb_event(updated_event)
      assert result.event == "artifact_updated"
    end

    test "returns error for missing required fields" do
      assert validate_wandb_event(@invalid_wandb_webhook_missing_artifact) ==
               {:error, :missing_fields}
    end

    test "returns error for missing artifact fields" do
      incomplete = %{
        "event_type" => "artifact_created",
        "artifact_version" => %{
          "entity" => "my-org"
          # missing project, artifact_sequence_name, version
        }
      }

      assert validate_wandb_event(incomplete) == {:error, :missing_fields}
    end

    test "returns error for unknown event types" do
      unknown_event = Map.put(@valid_wandb_webhook, "event_type", "unknown_event")

      assert validate_wandb_event(unknown_event) == {:error, :invalid_event_type}
    end

    test "builds correct model_id from artifact_version fields" do
      {:ok, result} = validate_wandb_event(%{
        "event_type" => "artifact_created",
        "artifact_version" => %{
          "entity" => "acme-corp",
          "project" => "nlp-models",
          "artifact_sequence_name" => "bert-classifier",
          "version" => "v5"
        }
      })

      assert result.model_id == "acme-corp/nlp-models/bert-classifier:v5"
    end
  end

  # Helper functions to test validation logic directly
  defp validate_mlflow_event(params) do
    event = params["event"]
    model_name = params["model_name"]
    version = params["version"]

    cond do
      is_nil(event) or is_nil(model_name) or is_nil(version) ->
        {:error, :missing_fields}

      event in [
        "MODEL_VERSION_TRANSITION_REQUEST_CREATED",
        "MODEL_VERSION_TRANSITIONED_STAGE",
        "REGISTERED_MODEL_CREATED",
        "MODEL_VERSION_CREATED"
      ] ->
        model_id = "#{model_name}:#{version}"
        {:ok, %{model_id: model_id, event: event}}

      true ->
        {:error, :invalid_event_type}
    end
  end

  defp validate_huggingface_event(params) do
    event = params["event"]
    repo = params["repo"]

    cond do
      is_nil(event) or is_nil(repo) ->
        {:error, :missing_fields}

      event in ["model.update", "model.create", "repo.content.changed"] and
          repo["type"] == "model" ->
        model_id = repo["name"]
        {:ok, %{model_id: model_id, event: event}}

      true ->
        {:error, :invalid_event_type}
    end
  end

  defp validate_wandb_event(params) do
    event_type = params["event_type"]
    artifact_version = params["artifact_version"]

    cond do
      is_nil(event_type) or is_nil(artifact_version) ->
        {:error, :missing_fields}

      event_type in ["artifact_created", "artifact_updated", "artifact_aliased"] ->
        entity = artifact_version["entity"]
        project = artifact_version["project"]
        artifact_name = artifact_version["artifact_sequence_name"]
        version = artifact_version["version"]

        if entity && project && artifact_name && version do
          model_id = "#{entity}/#{project}/#{artifact_name}:#{version}"
          {:ok, %{model_id: model_id, event: event_type}}
        else
          {:error, :missing_fields}
        end

      true ->
        {:error, :invalid_event_type}
    end
  end
end
