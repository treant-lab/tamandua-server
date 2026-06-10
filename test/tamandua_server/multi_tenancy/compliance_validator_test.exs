defmodule TamanduaServer.MultiTenancy.ComplianceValidatorTest do
  use TamanduaServer.DataCase

  alias TamanduaServer.MultiTenancy.ComplianceValidator
  alias TamanduaServer.Tenants

  describe "validate/2 - GDPR" do
    test "validates GDPR compliance for EU tenant with proper settings" do
      {:ok, org} = create_compliant_gdpr_org()

      assert {:ok, result} = ComplianceValidator.validate(org.id, :gdpr)
      assert result.framework == :gdpr
      assert is_list(result.checks)
      assert is_list(result.violations)
      assert result.validated_at
    end

    test "detects GDPR violations for incorrect region" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{"compliance_frameworks" => ["gdpr"]}
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :gdpr)
      assert result.compliant == false
      assert Enum.any?(result.violations, &(&1.check == "gdpr_data_residency"))
    end

    test "detects missing encryption" do
      {:ok, org} = create_org(%{
        region: :eu,
        settings: %{"encryption_enabled" => false}
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :gdpr)
      assert result.compliant == false
      assert Enum.any?(result.violations, &(&1.check == "gdpr_encryption"))
    end
  end

  describe "validate/2 - CCPA" do
    test "validates CCPA compliance" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "compliance_frameworks" => ["ccpa"],
          "privacy_notice_enabled" => true,
          "ccpa_opt_out_enabled" => true
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :ccpa)
      assert result.framework == :ccpa
    end

    test "detects missing opt-out mechanism" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "compliance_frameworks" => ["ccpa"],
          "ccpa_opt_out_enabled" => false
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :ccpa)
      assert result.compliant == false
      assert Enum.any?(result.violations, &(&1.check == "ccpa_opt_out"))
    end
  end

  describe "validate/2 - SOX" do
    test "validates SOX compliance" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "audit_logging_enabled" => true,
          "audit_retention_years" => 7,
          "rbac_enabled" => true,
          "mfa_required" => true
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :sox)
      assert result.framework == :sox
    end

    test "detects insufficient audit retention" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "audit_retention_years" => 3
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :sox)
      assert result.compliant == false
      assert Enum.any?(result.violations, &(&1.check == "sox_audit_trail"))
    end
  end

  describe "validate/2 - HIPAA" do
    test "validates HIPAA compliance" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "encryption_enabled" => true,
          "rbac_enabled" => true,
          "audit_logging_enabled" => true,
          "data_retention_years" => 6
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :hipaa)
      assert result.framework == :hipaa
    end

    test "detects missing PHI encryption" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "encryption_enabled" => false
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :hipaa)
      assert result.compliant == false
      assert Enum.any?(result.violations, &(&1.check == "hipaa_encryption"))
      assert Enum.any?(result.violations, &(&1.severity == "critical"))
    end
  end

  describe "validate/2 - PCI-DSS" do
    test "validates PCI-DSS compliance" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "encryption_enabled" => true,
          "rbac_enabled" => true,
          "audit_logging_enabled" => true,
          "audit_retention_years" => 1
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :pci_dss)
      assert result.framework == :pci_dss
    end
  end

  describe "validate/2 - SOC2" do
    test "validates SOC2 compliance" do
      {:ok, org} = create_org(%{
        region: :us,
        settings: %{
          "encryption_enabled" => true,
          "rbac_enabled" => true,
          "replication_enabled" => true
        }
      })

      assert {:ok, result} = ComplianceValidator.validate(org.id, :soc2)
      assert result.framework == :soc2
    end
  end

  describe "validate/2 - unsupported framework" do
    test "rejects unsupported framework" do
      {:ok, org} = create_org(%{region: :us})

      assert {:error, {:unsupported_framework, :invalid}} =
               ComplianceValidator.validate(org.id, :invalid)
    end
  end

  describe "audit_compliance/1" do
    test "runs full audit across all applicable frameworks" do
      {:ok, org} = create_org(%{
        region: :eu,
        settings: %{
          "compliance_frameworks" => ["gdpr", "sox"]
        }
      })

      result = ComplianceValidator.audit_compliance(org.id)

      assert is_map(result.results)
      assert Map.has_key?(result.results, :gdpr)
      assert Map.has_key?(result.results, :sox)
      assert is_boolean(result.overall_compliant)
      assert result.audited_at
    end
  end

  describe "generate_report/2" do
    test "generates compliance report" do
      {:ok, org} = create_compliant_gdpr_org()

      assert {:ok, report} = ComplianceValidator.generate_report(org.id, :gdpr)
      assert report.organization.id == org.id
      assert report.framework == :gdpr
      assert report.compliance_status in [:compliant, :non_compliant]
      assert is_list(report.violations)
      assert is_list(report.checks)
      assert is_list(report.recommendations)
      assert report.generated_at
    end

    test "generates report with evidence" do
      {:ok, org} = create_compliant_gdpr_org()

      assert {:ok, report} =
               ComplianceValidator.generate_report(org.id, :gdpr, include_evidence: true)

      assert Map.has_key?(report, :evidence)
    end
  end

  describe "check_data_location_compliance/2" do
    test "allows compliant data location" do
      {:ok, org} = create_org(%{region: :us})

      assert {:ok, :compliant} = ComplianceValidator.check_data_location_compliance(org.id, :us)
    end

    test "detects GDPR violations for non-EU storage" do
      {:ok, org} = create_org(%{
        region: :eu,
        settings: %{"compliance_frameworks" => ["gdpr"]}
      })

      assert {:error, {:compliance_violation, violations}} =
               ComplianceValidator.check_data_location_compliance(org.id, :us)

      assert :gdpr in violations
    end
  end

  describe "validate_encryption/1" do
    test "validates encryption is enabled" do
      {:ok, org} = create_org(%{
        settings: %{
          "encryption_enabled" => true,
          "compliance_frameworks" => ["hipaa"]
        }
      })

      assert {:ok, result} = ComplianceValidator.validate_encryption(org.id)
      assert result.compliant == true
      assert result.encryption_enabled == true
      assert :hipaa in result.frameworks_requiring_encryption
    end

    test "detects missing required encryption" do
      {:ok, org} = create_org(%{
        settings: %{
          "encryption_enabled" => false,
          "compliance_frameworks" => ["hipaa"]
        }
      })

      assert {:ok, result} = ComplianceValidator.validate_encryption(org.id)
      assert result.compliant == false
      assert result.encryption_required == true
    end
  end

  describe "validate_audit_retention/1" do
    test "validates retention meets requirements" do
      {:ok, org} = create_org(%{
        settings: %{
          "data_retention_days" => 2555,
          "compliance_frameworks" => ["gdpr"]
        }
      })

      assert {:ok, result} = ComplianceValidator.validate_audit_retention(org.id)
      assert result.compliant == true
      assert result.retention_days == 2555
    end

    test "detects insufficient retention" do
      {:ok, org} = create_org(%{
        settings: %{
          "data_retention_days" => 30,
          "compliance_frameworks" => ["sox"]
        }
      })

      assert {:ok, result} = ComplianceValidator.validate_audit_retention(org.id)
      assert result.compliant == false
    end
  end

  describe "supported_frameworks/0" do
    test "returns all supported frameworks" do
      frameworks = ComplianceValidator.supported_frameworks()

      assert :gdpr in frameworks
      assert :ccpa in frameworks
      assert :sox in frameworks
      assert :hipaa in frameworks
      assert :pci_dss in frameworks
      assert :soc2 in frameworks
    end
  end

  # Helper functions

  defp create_org(attrs) do
    base_attrs = %{
      name: "Test Org #{:rand.uniform(10000)}",
      slug: "test-org-#{:rand.uniform(10000)}",
      region: :us,
      settings: %{}
    }

    merged_attrs = Map.merge(base_attrs, attrs)
    Tenants.create_organization(merged_attrs)
  end

  defp create_compliant_gdpr_org do
    create_org(%{
      region: :eu,
      settings: %{
        "compliance_frameworks" => ["gdpr"],
        "encryption_enabled" => true,
        "audit_logging_enabled" => true,
        "rbac_enabled" => true,
        "data_retention_days" => 2555,
        "breach_notification_enabled" => true,
        "dpa_signed" => true,
        "right_to_erasure_enabled" => true
      }
    })
  end
end
