defmodule TamanduaServer.Detection.RuleLifecycleTest do
  use TamanduaServer.DataCase, async: true

  import TamanduaServer.AccountsFixtures

  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.{RuleLifecycle, RuleVersion}

  setup do
    organization = organization_fixture()
    user = user_fixture(%{organization_id: organization.id})

    {:ok, rule} =
      Detection.create_yara_rule(%{
        name: "LifecycleRule",
        author: "Detection Engineering",
        source: "rule LifecycleRule { condition: true }",
        organization_id: organization.id
      })

    insert_version!(rule, user.id, 1, "Initial import")
    insert_version!(rule, user.id, 2, "Validated update")

    %{organization: organization, rule: rule, user: user}
  end

  test "returns canonical state, owner, validation and ordered history", context do
    assert {:ok, lifecycle} =
             RuleLifecycle.describe(:yara, context.rule.id, context.organization.id)

    assert lifecycle.rule == %{
             id: context.rule.id,
             type: "yara",
             name: "LifecycleRule",
             state: "enabled",
             owner: %{
               content_author: "Detection Engineering",
               last_changed_by: context.user.id
             }
           }

    assert lifecycle.current_version == 2
    assert Enum.map(lifecycle.history, & &1.version) == [2, 1]

    assert lifecycle.validation == %{
             status: "passed",
             evidence_class: "smoke",
             validator: "syntax"
           }

    assert lifecycle.promotion_gate.decision == "review_required"
    assert lifecycle.promotion_gate.target_environment == "staging"
    assert lifecycle.promotion_gate.reasons == ["insufficient_evidence"]
  end

  test "allows staging only with passing synthetic parity evidence", context do
    assert {:ok, lifecycle} =
             RuleLifecycle.describe(:yara, context.rule.id, context.organization.id,
               target_environment: :staging,
               test_result: %{status: :passed, evidence_class: :synthetic_parity}
             )

    assert lifecycle.test_result == %{
             status: "passed",
             evidence_class: "synthetic_parity"
           }

    assert lifecycle.promotion_gate.decision == "eligible"
    assert lifecycle.promotion_gate.reasons == []
  end

  test "does not treat synthetic evidence as production-ready", context do
    assert {:ok, lifecycle} =
             RuleLifecycle.describe("yara", context.rule.id, context.organization.id,
               target_environment: "production",
               test_result: %{"status" => "passed", "evidence_class" => "synthetic_parity"}
             )

    assert lifecycle.promotion_gate.decision == "review_required"
    assert lifecycle.promotion_gate.required_evidence_class == "governed_holdout"
    assert lifecycle.promotion_gate.reasons == ["insufficient_evidence"]
  end

  test "a failed test blocks promotion", context do
    assert {:ok, lifecycle} =
             RuleLifecycle.describe(:yara, context.rule.id, context.organization.id,
               target_environment: :development,
               test_result: %{status: :failed, evidence_class: :synthetic_parity}
             )

    assert lifecycle.promotion_gate.decision == "blocked"
    assert "test_failed" in lifecycle.promotion_gate.reasons
  end

  test "tenant scope prevents lifecycle disclosure", context do
    other_organization = organization_fixture()

    assert {:error, :not_found} =
             RuleLifecycle.describe(:yara, context.rule.id, other_organization.id)
  end

  test "rejects unsupported rule types and malformed test evidence", context do
    assert {:error, :unsupported_rule_type} =
             RuleLifecycle.describe(:suricata, context.rule.id, context.organization.id)

    assert {:error, :invalid_test_result} =
             RuleLifecycle.describe(:yara, context.rule.id, context.organization.id,
               test_result: %{status: :passed, evidence_class: :unknown}
             )
  end

  defp insert_version!(rule, user_id, version, summary) do
    rule
    |> RuleVersion.from_rule(:yara, user_id, summary)
    |> RuleVersion.changeset(%{version: version})
    |> Repo.insert!()
  end
end
