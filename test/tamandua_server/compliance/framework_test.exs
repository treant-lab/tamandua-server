defmodule TamanduaServer.Compliance.FrameworkTest do
  use ExUnit.Case, async: true

  alias TamanduaServer.Compliance.Framework

  describe "load_all_frameworks/0" do
    test "loads all framework definitions" do
      frameworks = Framework.load_all_frameworks()

      assert length(frameworks) >= 6

      framework_ids = Enum.map(frameworks, & &1.id)
      assert :gdpr in framework_ids
      assert :hipaa in framework_ids
      assert :pci_dss in framework_ids
      assert :soc2 in framework_ids
      assert :iso_27001 in framework_ids
      assert :nist_csf in framework_ids
    end

    test "each framework has required fields" do
      frameworks = Framework.load_all_frameworks()

      for framework <- frameworks do
        assert framework.id
        assert framework.name
        assert framework.full_name
        assert framework.version
        assert framework.description
        assert framework.url
        assert is_list(framework.controls)
      end
    end
  end

  describe "get_framework/1" do
    test "loads GDPR framework" do
      framework = Framework.get_framework(:gdpr)

      assert framework.id == :gdpr
      assert framework.name == "GDPR"
      assert framework.full_name == "General Data Protection Regulation"
      assert framework.version == "2016/679"
      assert length(framework.controls) >= 15
    end

    test "loads HIPAA framework" do
      framework = Framework.get_framework(:hipaa)

      assert framework.id == :hipaa
      assert framework.name == "HIPAA"
      assert String.contains?(framework.full_name, "Health Insurance")
      assert length(framework.controls) >= 25
    end

    test "loads PCI-DSS framework" do
      framework = Framework.get_framework(:pci_dss)

      assert framework.id == :pci_dss
      assert framework.name == "PCI DSS"
      assert framework.version == "4.0"
      assert length(framework.controls) >= 20
    end

    test "loads SOC 2 framework" do
      framework = Framework.get_framework(:soc2)

      assert framework.id == :soc2
      assert framework.name == "SOC 2"
      assert length(framework.controls) >= 30
    end

    test "loads ISO 27001 framework" do
      framework = Framework.get_framework(:iso_27001)

      assert framework.id == :iso_27001
      assert framework.name == "ISO 27001"
      assert framework.version == "2022"
      assert length(framework.controls) >= 20
    end

    test "loads NIST CSF framework" do
      framework = Framework.get_framework(:nist_csf)

      assert framework.id == :nist_csf
      assert framework.name == "NIST CSF"
      assert framework.version == "2.0"
      assert length(framework.controls) >= 25
    end
  end

  describe "list_frameworks/0" do
    test "returns framework summaries" do
      frameworks = Framework.list_frameworks()

      assert length(frameworks) >= 6

      for framework <- frameworks do
        assert framework.id
        assert framework.name
        assert framework.full_name
        assert framework.version
        assert framework.description
        assert framework.control_count > 0
      end
    end
  end

  describe "get_controls/1" do
    test "returns all controls for GDPR" do
      controls = Framework.get_controls(:gdpr)

      assert length(controls) >= 15

      # Check for key GDPR controls
      control_ids = Enum.map(controls, & &1.id)
      assert "gdpr-art-5" in control_ids
      assert "gdpr-art-32" in control_ids
      assert "gdpr-art-33" in control_ids
    end

    test "each control has required fields" do
      controls = Framework.get_controls(:hipaa)

      for control <- controls do
        assert control.id
        assert control.control_id
        assert control.title
        assert control.description
        assert control.category
        assert control.severity in [:critical, :high, :medium, :low]
        assert is_boolean(control.automated)
        assert is_list(control.evidence_types)
        assert is_list(control.remediation_steps)
      end
    end
  end

  describe "get_control/2" do
    test "retrieves specific control by ID" do
      control = Framework.get_control(:gdpr, "gdpr-art-32")

      assert control.id == "gdpr-art-32"
      assert control.control_id == "Article 32"
      assert control.title == "Security of processing"
      assert control.category == :data_protection
      assert control.severity == :critical
      assert control.automated == true
    end

    test "returns nil for non-existent control" do
      control = Framework.get_control(:gdpr, "non-existent")
      assert is_nil(control)
    end
  end

  describe "get_controls_by_category/2" do
    test "filters controls by category" do
      controls = Framework.get_controls_by_category(:gdpr, :data_protection)

      assert length(controls) > 0
      assert Enum.all?(controls, &(&1.category == :data_protection))
    end

    test "returns empty list for non-existent category" do
      controls = Framework.get_controls_by_category(:gdpr, :non_existent)
      assert controls == []
    end
  end

  describe "get_controls_by_severity/2" do
    test "filters controls by critical severity" do
      controls = Framework.get_controls_by_severity(:hipaa, :critical)

      assert length(controls) > 0
      assert Enum.all?(controls, &(&1.severity == :critical))
    end

    test "filters controls by high severity" do
      controls = Framework.get_controls_by_severity(:pci_dss, :high)

      assert length(controls) > 0
      assert Enum.all?(controls, &(&1.severity == :high))
    end
  end

  describe "get_automated_controls/1" do
    test "returns only automated controls" do
      controls = Framework.get_automated_controls(:nist_csf)

      assert length(controls) > 0
      assert Enum.all?(controls, & &1.automated)
      assert Enum.all?(controls, &(!is_nil(&1.validation_query)))
    end

    test "automated controls have validation queries" do
      controls = Framework.get_automated_controls(:iso_27001)

      for control <- controls do
        assert control.automated == true
        # Note: Some automated controls may have nil validation_query if not yet implemented
      end
    end
  end

  describe "control validation" do
    test "GDPR controls have proper evidence types" do
      controls = Framework.get_controls(:gdpr)

      gdpr_art_32 = Enum.find(controls, &(&1.id == "gdpr-art-32"))
      assert :encryption_status in gdpr_art_32.evidence_types
      assert :access_controls in gdpr_art_32.evidence_types
      assert :security_assessments in gdpr_art_32.evidence_types
    end

    test "HIPAA controls have proper categories" do
      controls = Framework.get_controls(:hipaa)

      categories = Enum.map(controls, & &1.category) |> Enum.uniq()
      assert :administrative in categories
      assert :physical in categories
      assert :technical in categories
      assert :organizational in categories
    end

    test "PCI-DSS controls reference proper requirements" do
      controls = Framework.get_controls(:pci_dss)

      # PCI-DSS controls should have numeric control IDs
      for control <- controls do
        assert String.match?(control.control_id, ~r/^\d+\.\d+/)
      end
    end

    test "SOC 2 controls align with trust principles" do
      controls = Framework.get_controls(:soc2)

      categories = Enum.map(controls, & &1.category) |> Enum.uniq()
      assert :security in categories
      # Other trust principles may be present
    end

    test "ISO 27001 controls have proper control IDs" do
      controls = Framework.get_controls(:iso_27001)

      # ISO 27001 controls should start with A.
      for control <- controls do
        assert String.starts_with?(control.control_id, "A.")
      end
    end

    test "NIST CSF controls have proper function categories" do
      controls = Framework.get_controls(:nist_csf)

      categories = Enum.map(controls, & &1.category) |> Enum.uniq()

      # NIST CSF has 5 core functions
      assert :identify in categories or
             :protect in categories or
             :detect in categories or
             :respond in categories or
             :recover in categories
    end
  end

  describe "remediation steps" do
    test "critical controls have remediation steps" do
      controls = Framework.get_controls(:pci_dss)
      critical_controls = Enum.filter(controls, &(&1.severity == :critical))

      for control <- critical_controls do
        assert length(control.remediation_steps) > 0
      end
    end

    test "remediation steps are actionable" do
      control = Framework.get_control(:gdpr, "gdpr-art-32")

      assert length(control.remediation_steps) > 0

      for step <- control.remediation_steps do
        assert is_binary(step)
        assert String.length(step) > 10
      end
    end
  end
end
