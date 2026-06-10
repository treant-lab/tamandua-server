defmodule TamanduaServer.Detection.RuleImporterTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.Detection.{RuleImporter, RuleValidator, RuleImportJob}
  alias TamanduaServer.Repo

  describe "validate_yara/1" do
    test "validates correct YARA rule" do
      rule = """
      rule TestRule {
        meta:
          description = "Test rule"
          author = "Test Author"
        strings:
          $a = "malicious"
        condition:
          $a
      }
      """

      assert {:ok, metadata} = RuleValidator.validate_yara(rule)
      assert metadata.name == "TestRule"
    end

    test "rejects invalid YARA syntax" do
      assert {:error, _} = RuleValidator.validate_yara("invalid rule")
    end
  end

  describe "validate_sigma/1" do
    test "validates correct Sigma rule" do
      yaml = """
      title: Test Sigma Rule
      description: A test rule
      logsource:
        category: process_creation
        product: windows
      detection:
        selection:
          CommandLine: "*malicious*"
        condition: selection
      """

      assert {:ok, parsed} = RuleValidator.validate_sigma(yaml)
      assert parsed.title == "Test Sigma Rule"
    end

    test "rejects invalid Sigma YAML" do
      assert {:error, _} = RuleValidator.validate_sigma("title: test\ndetection: invalid")
    end
  end

  describe "validate_ioc/1" do
    test "validates correct IOC" do
      ioc = %{
        "type" => "hash_sha256",
        "value" => "abc123",
        "description" => "Test IOC"
      }

      assert {:ok, normalized} = RuleValidator.validate_ioc(ioc)
      assert normalized.type == "hash_sha256"
      assert normalized.value == "abc123"
    end

    test "rejects invalid IOC type" do
      ioc = %{"type" => "invalid", "value" => "test"}
      assert {:error, _} = RuleValidator.validate_ioc(ioc)
    end
  end

  describe "import_from_content/2" do
    setup do
      org_id = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      job_attrs = %{
        type: "yara",
        source_type: "file",
        conflict_resolution: "skip",
        validation_enabled: true,
        organization_id: org_id,
        user_id: user_id,
        metadata: %{}
      }

      {:ok, job_attrs: job_attrs, org_id: org_id}
    end

    test "imports YARA rule successfully", %{job_attrs: job_attrs} do
      content = """
      rule TestMalware {
        strings:
          $s1 = "malicious"
        condition:
          $s1
      }
      """

      job = struct(RuleImportJob, job_attrs)

      assert {:ok, stats} = RuleImporter.import_from_content(content, job)
      assert stats.imported_rules == 1
      assert stats.failed_rules == 0
    end

    test "handles duplicate rules with skip resolution", %{job_attrs: job_attrs, org_id: org_id} do
      # Create initial rule
      {:ok, _} = TamanduaServer.Detection.create_yara_rule(%{
        name: "TestMalware",
        source: "rule TestMalware { condition: true }",
        organization_id: org_id
      })

      # Try to import duplicate
      content = "rule TestMalware { condition: true }"
      job = struct(RuleImportJob, job_attrs)

      assert {:ok, stats} = RuleImporter.import_from_content(content, job)
      assert stats.skipped_rules == 1
    end
  end
end
