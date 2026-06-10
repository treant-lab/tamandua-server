defmodule TamanduaServer.Detection.ChainLibraryTest do
  use TamanduaServer.DataCase, async: true

  alias TamanduaServer.Detection.{ChainLibrary, AttackChain}
  alias TamanduaServer.Repo

  setup do
    org = insert(:organization)
    {:ok, %{org: org}}
  end

  describe "get_builtin_chains/0" do
    test "returns all built-in chain definitions" do
      chains = ChainLibrary.get_builtin_chains()

      assert length(chains) >= 10
      assert Enum.all?(chains, &is_map/1)
      assert Enum.all?(chains, &Map.has_key?(&1, :name))
      assert Enum.all?(chains, &Map.has_key?(&1, :definition))
    end

    test "all chains have valid step definitions" do
      chains = ChainLibrary.get_builtin_chains()

      Enum.each(chains, fn chain ->
        assert is_map(chain.definition)
        assert is_list(chain.definition["steps"])
        assert length(chain.definition["steps"]) > 0

        Enum.each(chain.definition["steps"], fn step ->
          assert is_map(step)
          assert is_list(step["techniques"])
          assert length(step["techniques"]) > 0
        end)
      end)
    end

    test "all chains have required metadata" do
      chains = ChainLibrary.get_builtin_chains()

      Enum.each(chains, fn chain ->
        assert chain.name
        assert chain.description
        assert chain.severity in ["critical", "high", "medium", "low", "info"]
        assert chain.author
        assert is_list(chain.tags)
      end)
    end
  end

  describe "install_builtin_chains/1" do
    test "installs all built-in chains for organization", %{org: org} do
      {:ok, result} = ChainLibrary.install_builtin_chains(org.id)

      assert result.installed > 0
      assert result.failed == 0

      chains = Repo.all(AttackChain)
      assert length(chains) > 0

      # Verify chains have correct org_id
      assert Enum.all?(chains, &(&1.organization_id == org.id))
    end

    test "updates existing chains on reinstall", %{org: org} do
      # First install
      {:ok, result1} = ChainLibrary.install_builtin_chains(org.id)

      # Modify a chain
      chain = Repo.get_by!(AttackChain, name: "Credential Stuffing to Account Takeover")
      {:ok, _} = chain |> AttackChain.changeset(%{enabled: false}) |> Repo.update()

      # Reinstall
      {:ok, result2} = ChainLibrary.install_builtin_chains(org.id)

      assert result1.installed == result2.installed

      # Verify chain was updated
      updated = Repo.get!(AttackChain, chain.id)
      assert updated.enabled == true
    end
  end

  describe "import_from_yaml/2" do
    test "imports chain from valid YAML", %{org: org} do
      yaml = """
      name: "Test Import Chain"
      description: "Imported chain"
      severity: high
      definition:
        steps:
          - name: "Step 1"
            techniques:
              - T1110
            threshold: 1
            timeframe: 300
      """

      {:ok, chain} = ChainLibrary.import_from_yaml(yaml, org.id)

      assert chain.name == "Test Import Chain"
      assert chain.organization_id == org.id
      assert is_map(chain.definition)
    end

    test "returns error for invalid YAML", %{org: org} do
      yaml = "invalid: yaml: content: ["

      assert {:error, _} = ChainLibrary.import_from_yaml(yaml, org.id)
    end

    test "returns error for YAML without required fields", %{org: org} do
      yaml = """
      name: "Incomplete Chain"
      """

      assert {:error, _} = ChainLibrary.import_from_yaml(yaml, org.id)
    end
  end

  describe "export_to_yaml/1" do
    test "exports chain to YAML format", %{org: org} do
      chain =
        insert(:attack_chain,
          organization: org,
          name: "Export Test",
          definition: %{
            "steps" => [
              %{
                "name" => "Step 1",
                "techniques" => ["T1110"],
                "threshold" => 1,
                "timeframe" => 300
              }
            ]
          }
        )

      {:ok, yaml} = ChainLibrary.export_to_yaml(chain.id)

      assert is_binary(yaml)
      assert yaml =~ "steps"
      assert yaml =~ "T1110"
    end

    test "returns error for non-existent chain" do
      assert {:error, :not_found} = ChainLibrary.export_to_yaml(Ecto.UUID.generate())
    end
  end

  describe "specific chain definitions" do
    test "credential stuffing chain has correct structure" do
      chains = ChainLibrary.get_builtin_chains()
      chain = Enum.find(chains, &(&1.name == "Credential Stuffing to Account Takeover"))

      assert chain
      assert chain.severity == "critical"
      assert length(chain.definition["steps"]) == 2

      [step1, step2] = chain.definition["steps"]
      assert "T1110" in step1["techniques"]
      assert "T1078" in step2["techniques"]
      assert step2["conditions"]["same_user"] == true
    end

    test "ransomware kill chain has correct structure" do
      chains = ChainLibrary.get_builtin_chains()
      chain = Enum.find(chains, &(&1.name == "Ransomware Kill Chain"))

      assert chain
      assert chain.severity == "critical"
      assert length(chain.definition["steps"]) == 3

      steps = chain.definition["steps"]
      techniques = Enum.flat_map(steps, & &1["techniques"])
      assert "T1486" in techniques
      assert "T1490" in techniques
    end

    test "lateral movement chain has correct conditions" do
      chains = ChainLibrary.get_builtin_chains()
      chain = Enum.find(chains, &(&1.name == "Reconnaissance to Lateral Movement"))

      assert chain
      steps = chain.definition["steps"]
      assert length(steps) == 3

      # Later steps should have same_agent or same_user conditions
      [_step1, step2, step3] = steps
      assert step2["conditions"]["same_agent"] == true
      assert step3["conditions"]["same_user"] == true
    end

    test "all chains have narrative templates" do
      chains = ChainLibrary.get_builtin_chains()

      Enum.each(chains, fn chain ->
        assert chain.definition["narrative_template"]
        assert is_binary(chain.definition["narrative_template"])
      end)
    end

    test "all chains have valid MITRE techniques" do
      chains = ChainLibrary.get_builtin_chains()

      Enum.each(chains, fn chain ->
        steps = chain.definition["steps"]

        Enum.each(steps, fn step ->
          techniques = step["techniques"]

          Enum.each(techniques, fn technique ->
            # Basic validation: should start with T followed by numbers
            assert technique =~ ~r/^T\d+/
          end)
        end)
      end)
    end
  end
end
