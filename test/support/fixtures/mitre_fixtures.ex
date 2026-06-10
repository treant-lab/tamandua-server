defmodule TamanduaServer.MitreFixtures do
  @moduledoc """
  Test fixtures for MITRE ATT&CK integration tests.
  """

  alias TamanduaServer.Repo
  alias TamanduaServer.Mitre.{Technique, TechniqueMapping, ThreatActor, NavigatorLayer}

  @doc """
  Generate a MITRE technique fixture.

  ## Examples

      iex> technique_fixture()
      %Technique{technique_id: "T1059", ...}

      iex> technique_fixture(technique_id: "T1055.001", is_subtechnique: true)
      %Technique{technique_id: "T1055.001", is_subtechnique: true, ...}
  """
  def technique_fixture(attrs \\ %{}) do
    {technique_id, attrs} = Map.pop(attrs, :technique_id, "T#{:rand.uniform(9999)}")
    is_subtechnique = String.contains?(technique_id, ".")

    attrs =
      Enum.into(attrs, %{
        technique_id: technique_id,
        name: attrs[:name] || "Test Technique #{technique_id}",
        description: attrs[:description] || "Test description for #{technique_id}",
        platforms: attrs[:platforms] || ["windows", "linux"],
        tactics: attrs[:tactics] || ["TA0002"],
        is_subtechnique: attrs[:is_subtechnique] || is_subtechnique,
        parent_technique_id: attrs[:parent_technique_id] || (if is_subtechnique, do: String.split(technique_id, ".") |> List.first(), else: nil),
        data_sources: attrs[:data_sources] || ["Process: Process Creation"],
        detection_guidance: attrs[:detection_guidance] || "Monitor for suspicious activity"
      })

    %Technique{}
    |> Technique.changeset(attrs)
    |> Repo.insert!()
  end

  @doc """
  Generate a technique mapping fixture.
  """
  def technique_mapping_fixture(attrs \\ %{}) do
    attrs =
      Enum.into(attrs, %{
        technique_id: attrs[:technique_id] || "T1059",
        rule_type: attrs[:rule_type] || "sigma",
        rule_id: attrs[:rule_id] || Ecto.UUID.generate(),
        rule_name: attrs[:rule_name] || "Test Rule",
        confidence: attrs[:confidence] || 1.0,
        auto_mapped: attrs[:auto_mapped] || true,
        organization_id: attrs[:organization_id]
      })

    %TechniqueMapping{}
    |> TechniqueMapping.changeset(attrs)
    |> Repo.insert!()
  end

  @doc """
  Generate a threat actor fixture.
  """
  def threat_actor_fixture(attrs \\ %{}) do
    attrs =
      Enum.into(attrs, %{
        actor_id: attrs[:actor_id] || "G#{:rand.uniform(9999)}",
        name: attrs[:name] || "Test Threat Actor",
        aliases: attrs[:aliases] || ["TestAPT"],
        description: attrs[:description] || "Test threat actor description",
        techniques: attrs[:techniques] || ["T1059", "T1055"],
        country: attrs[:country] || "Unknown",
        sophistication: attrs[:sophistication] || "medium",
        objectives: attrs[:objectives] || ["espionage"],
        sectors: attrs[:sectors] || ["technology"]
      })

    %ThreatActor{}
    |> ThreatActor.changeset(attrs)
    |> Repo.insert!()
  end

  @doc """
  Generate a Navigator layer fixture.
  """
  def navigator_layer_fixture(attrs \\ %{}) do
    layer_data = %{
      "name" => "Test Layer",
      "versions" => %{
        "attack" => "14",
        "navigator" => "4.9",
        "layer" => "4.5"
      },
      "domain" => "enterprise-attack",
      "techniques" => [
        %{
          "techniqueID" => "T1059",
          "score" => 75,
          "comment" => "Test technique"
        }
      ]
    }

    attrs =
      Enum.into(attrs, %{
        name: attrs[:name] || "Test Layer",
        description: attrs[:description] || "Test layer description",
        layer_data: attrs[:layer_data] || layer_data,
        layer_type: attrs[:layer_type] || "coverage",
        is_public: attrs[:is_public] || false,
        organization_id: attrs[:organization_id],
        created_by_id: attrs[:created_by_id]
      })

    %NavigatorLayer{}
    |> NavigatorLayer.changeset(attrs)
    |> Repo.insert!()
  end

  @doc """
  Generate a minimal STIX attack-pattern object for testing imports.
  """
  def stix_technique_fixture(attrs \\ %{}) do
    technique_id = attrs[:technique_id] || "T1059"

    %{
      "type" => "attack-pattern",
      "id" => "attack-pattern--#{Ecto.UUID.generate()}",
      "created" => "2024-02-20T00:00:00.000Z",
      "modified" => "2024-02-20T00:00:00.000Z",
      "name" => attrs[:name] || "Command and Scripting Interpreter",
      "description" => attrs[:description] || "Adversaries may abuse command interpreters",
      "kill_chain_phases" => attrs[:kill_chain_phases] || [
        %{
          "kill_chain_name" => "mitre-attack",
          "phase_name" => "execution"
        }
      ],
      "external_references" => [
        %{
          "source_name" => "mitre-attack",
          "external_id" => technique_id,
          "url" => "https://attack.mitre.org/techniques/#{technique_id}"
        }
      ],
      "x_mitre_platforms" => attrs[:platforms] || ["Windows", "Linux"],
      "x_mitre_data_sources" => attrs[:data_sources] || ["Process: Process Creation"],
      "x_mitre_detection" => attrs[:detection] || "Monitor process creation",
      "x_mitre_version" => "2.0"
    }
  end

  @doc """
  Generate a minimal STIX intrusion-set object for testing threat actor imports.
  """
  def stix_threat_actor_fixture(attrs \\ %{}) do
    actor_id = attrs[:actor_id] || "G0016"

    %{
      "type" => "intrusion-set",
      "id" => "intrusion-set--#{Ecto.UUID.generate()}",
      "created" => "2024-02-20T00:00:00.000Z",
      "modified" => "2024-02-20T00:00:00.000Z",
      "name" => attrs[:name] || "Test APT",
      "description" => attrs[:description] || "Test threat actor description",
      "aliases" => attrs[:aliases] || ["TestAPT", "Test Group"],
      "external_references" => [
        %{
          "source_name" => "mitre-attack",
          "external_id" => actor_id,
          "url" => "https://attack.mitre.org/groups/#{actor_id}"
        }
      ],
      "x_mitre_country" => attrs[:country],
      "x_mitre_sophistication" => attrs[:sophistication] || "high"
    }
  end

  @doc """
  Generate a complete STIX bundle with techniques and threat actors.
  """
  def stix_bundle_fixture(opts \\ []) do
    technique_count = Keyword.get(opts, :technique_count, 3)
    actor_count = Keyword.get(opts, :actor_count, 2)

    techniques = for i <- 1..technique_count do
      stix_technique_fixture(technique_id: "T#{1000 + i}")
    end

    actors = for i <- 1..actor_count do
      stix_threat_actor_fixture(actor_id: "G#{1000 + i}")
    end

    %{
      "type" => "bundle",
      "id" => "bundle--#{Ecto.UUID.generate()}",
      "spec_version" => "2.0",
      "objects" => techniques ++ actors
    }
  end
end
