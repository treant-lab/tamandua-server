defmodule TamanduaServer.Detection.ChainLibrary do
  @moduledoc """
  Built-in library of pre-configured attack chains.

  Provides 10+ common attack chain patterns based on real-world attack scenarios
  and MITRE ATT&CK kill chains.
  """

  require Logger
  alias TamanduaServer.Detection.AttackChain
  alias TamanduaServer.Repo

  @doc """
  Get all built-in attack chain definitions.
  """
  def get_builtin_chains do
    [
      credential_stuffing_to_takeover(),
      recon_to_lateral_movement(),
      initial_access_to_exfiltration(),
      password_spray_to_privilege_escalation(),
      file_download_to_c2(),
      phishing_to_persistence(),
      living_off_the_land_chain(),
      ransomware_kill_chain(),
      data_theft_chain(),
      insider_threat_chain(),
      web_shell_deployment_chain(),
      supply_chain_attack_chain(),
      cloud_credential_theft_chain()
    ]
  end

  @doc """
  Install all built-in chains for an organization.
  """
  def install_builtin_chains(organization_id) do
    chains = get_builtin_chains()

    results =
      Enum.map(chains, fn chain_def ->
        install_chain(chain_def, organization_id)
      end)

    {successes, failures} = Enum.split_with(results, &match?({:ok, _}, &1))

    Logger.info(
      "[ChainLibrary] Installed #{length(successes)}/#{length(chains)} chains for org #{organization_id}"
    )

    if length(failures) > 0 do
      Logger.warning("[ChainLibrary] Failed to install #{length(failures)} chains")
    end

    {:ok, %{installed: length(successes), failed: length(failures)}}
  end

  @doc """
  Import a chain from YAML file.
  """
  def import_from_yaml(yaml_content, organization_id) do
    with {:ok, definition} <- AttackChain.parse_yaml(yaml_content),
         {:ok, chain} <- create_chain_from_definition(definition, organization_id) do
      {:ok, chain}
    end
  end

  @doc """
  Export a chain to YAML format.
  """
  def export_to_yaml(chain_id) do
    case Repo.get(AttackChain, chain_id) do
      nil -> {:error, :not_found}
      chain -> {:ok, AttackChain.to_yaml(chain)}
    end
  end

  # ─────────────────────────────────────────────────────────────────────
  # Built-in Chain Definitions
  # ─────────────────────────────────────────────────────────────────────

  defp credential_stuffing_to_takeover do
    %{
      name: "Credential Stuffing to Account Takeover",
      description: "Detects brute force attempts followed by successful account compromise",
      severity: "critical",
      author: "Tamandua EDR",
      tags: ["credential-access", "initial-access"],
      definition: %{
        "steps" => [
          %{
            "name" => "Brute Force Detection",
            "techniques" => ["T1110", "T1110.001", "T1110.003"],
            "threshold" => 3,
            "timeframe" => 300,
            "description" => "Multiple failed authentication attempts"
          },
          %{
            "name" => "Valid Account Login",
            "techniques" => ["T1078", "T1078.001", "T1078.002"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_user" => true},
            "description" => "Successful login after brute force"
          }
        ],
        "narrative_template" =>
          "Credential stuffing attack detected: {count} brute force attempts followed by successful login as user {user} from {source_ip} within {timespan}"
      }
    }
  end

  defp recon_to_lateral_movement do
    %{
      name: "Reconnaissance to Lateral Movement",
      description: "Discovery activities followed by lateral movement attempts",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["discovery", "lateral-movement"],
      definition: %{
        "steps" => [
          %{
            "name" => "Network Discovery",
            "techniques" => ["T1046", "T1018", "T1135"],
            "threshold" => 2,
            "timeframe" => 600,
            "description" => "Network scanning and service discovery"
          },
          %{
            "name" => "Account Discovery",
            "techniques" => ["T1087", "T1087.001", "T1087.002"],
            "threshold" => 1,
            "timeframe" => 900,
            "conditions" => %{"same_agent" => true},
            "description" => "User and group enumeration"
          },
          %{
            "name" => "Lateral Movement",
            "techniques" => ["T1021", "T1021.001", "T1021.002", "T1021.006"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_user" => true},
            "description" => "Remote service access to other systems"
          }
        ],
        "narrative_template" =>
          "Lateral movement chain detected: reconnaissance activities followed by remote access from {user} on {process} within {timespan}"
      }
    }
  end

  defp initial_access_to_exfiltration do
    %{
      name: "Initial Access to Data Exfiltration",
      description: "Complete kill chain from initial compromise to data theft",
      severity: "critical",
      author: "Tamandua EDR",
      tags: ["kill-chain", "exfiltration"],
      definition: %{
        "steps" => [
          %{
            "name" => "Initial Access",
            "techniques" => ["T1566", "T1566.001", "T1566.002", "T1189", "T1190"],
            "threshold" => 1,
            "timeframe" => 3600,
            "description" => "Phishing or exploit-based initial access"
          },
          %{
            "name" => "Execution",
            "techniques" => ["T1059", "T1059.001", "T1059.003", "T1204"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "Malicious code execution"
          },
          %{
            "name" => "Persistence",
            "techniques" => ["T1547", "T1053", "T1543"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_agent" => true},
            "description" => "Persistence mechanism established"
          },
          %{
            "name" => "Data Collection",
            "techniques" => ["T1005", "T1039", "T1074"],
            "threshold" => 1,
            "timeframe" => 7200,
            "conditions" => %{"same_agent" => true},
            "description" => "Data staged for exfiltration"
          },
          %{
            "name" => "Exfiltration",
            "techniques" => ["T1041", "T1048", "T1567"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_agent" => true},
            "description" => "Data exfiltrated from network"
          }
        ],
        "narrative_template" =>
          "Complete attack chain detected: initial access through {process} leading to data exfiltration to {source_ip} over {timespan}"
      }
    }
  end

  defp password_spray_to_privilege_escalation do
    %{
      name: "Password Spray to Privilege Escalation",
      description: "Password spraying attack followed by privilege escalation",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["credential-access", "privilege-escalation"],
      definition: %{
        "steps" => [
          %{
            "name" => "Password Spray",
            "techniques" => ["T1110.003"],
            "threshold" => 5,
            "timeframe" => 600,
            "description" => "Multiple users targeted with same password"
          },
          %{
            "name" => "Valid Account Compromise",
            "techniques" => ["T1078"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_source_ip" => true},
            "description" => "Successful authentication"
          },
          %{
            "name" => "Privilege Escalation",
            "techniques" => ["T1068", "T1134", "T1548"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Elevation to administrator privileges"
          }
        ],
        "narrative_template" =>
          "Password spray attack from {source_ip} compromised user {user} and escalated to administrator within {timespan}"
      }
    }
  end

  defp file_download_to_c2 do
    %{
      name: "File Download to C2 Communication",
      description: "Malicious file download followed by command and control activity",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["execution", "command-and-control"],
      definition: %{
        "steps" => [
          %{
            "name" => "File Download",
            "techniques" => ["T1105", "T1071.001"],
            "threshold" => 1,
            "timeframe" => 900,
            "description" => "Suspicious file downloaded from internet"
          },
          %{
            "name" => "Execution",
            "techniques" => ["T1204", "T1059"],
            "threshold" => 1,
            "timeframe" => 600,
            "conditions" => %{"same_agent" => true},
            "description" => "Downloaded file executed"
          },
          %{
            "name" => "C2 Communication",
            "techniques" => ["T1071", "T1071.001", "T1071.004", "T1095"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_process" => true},
            "description" => "Outbound C2 beaconing detected"
          }
        ],
        "narrative_template" =>
          "Malware infection detected: file downloaded and executed by {process}, establishing C2 to {source_ip} within {timespan}"
      }
    }
  end

  defp phishing_to_persistence do
    %{
      name: "Phishing to Persistence",
      description: "Email-based initial access followed by persistence establishment",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["initial-access", "persistence"],
      definition: %{
        "steps" => [
          %{
            "name" => "Phishing Email Execution",
            "techniques" => ["T1566.001", "T1566.002"],
            "threshold" => 1,
            "timeframe" => 1800,
            "description" => "User interaction with phishing email"
          },
          %{
            "name" => "Payload Execution",
            "techniques" => ["T1204.002", "T1059.005"],
            "threshold" => 1,
            "timeframe" => 600,
            "conditions" => %{"same_agent" => true},
            "description" => "Malicious attachment or script executed"
          },
          %{
            "name" => "Persistence Mechanism",
            "techniques" => ["T1547.001", "T1053.005", "T1543.003"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "Autostart or scheduled task created"
          }
        ],
        "narrative_template" =>
          "Phishing attack succeeded: user {user} executed malicious content and attacker established persistence via {process} within {timespan}"
      }
    }
  end

  defp living_off_the_land_chain do
    %{
      name: "Living off the Land Attack Chain",
      description: "Abuse of legitimate system tools for malicious purposes",
      severity: "medium",
      author: "Tamandua EDR",
      tags: ["defense-evasion", "lolbas"],
      definition: %{
        "steps" => [
          %{
            "name" => "LOLBin File Download",
            "techniques" => ["T1105", "T1218.011"],
            "threshold" => 1,
            "timeframe" => 900,
            "description" => "Abuse of certutil, bitsadmin, or similar"
          },
          %{
            "name" => "Script Execution",
            "techniques" => ["T1059.001", "T1059.003", "T1059.005"],
            "threshold" => 1,
            "timeframe" => 600,
            "conditions" => %{"same_agent" => true},
            "description" => "PowerShell or command shell script"
          },
          %{
            "name" => "Defense Evasion",
            "techniques" => ["T1027", "T1140", "T1070"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "Obfuscation or log clearing"
          }
        ],
        "narrative_template" =>
          "LOLBAS attack chain: legitimate tools abused by {user} for file download and script execution within {timespan}"
      }
    }
  end

  defp ransomware_kill_chain do
    %{
      name: "Ransomware Kill Chain",
      description: "Multi-stage ransomware deployment and execution",
      severity: "critical",
      author: "Tamandua EDR",
      tags: ["impact", "ransomware"],
      definition: %{
        "steps" => [
          %{
            "name" => "Discovery",
            "techniques" => ["T1083", "T1082"],
            "threshold" => 2,
            "timeframe" => 600,
            "description" => "File and system enumeration"
          },
          %{
            "name" => "Defense Inhibition",
            "techniques" => ["T1562", "T1562.001", "T1490"],
            "threshold" => 1,
            "timeframe" => 900,
            "conditions" => %{"same_agent" => true},
            "description" => "Security tools disabled or backups deleted"
          },
          %{
            "name" => "Data Encryption",
            "techniques" => ["T1486"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "File encryption for impact"
          }
        ],
        "narrative_template" =>
          "RANSOMWARE ATTACK: {process} enumerated system, disabled defenses, and encrypted files within {timespan}"
      }
    }
  end

  defp data_theft_chain do
    %{
      name: "Data Theft Operation",
      description: "Targeted data collection and exfiltration",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["collection", "exfiltration"],
      definition: %{
        "steps" => [
          %{
            "name" => "Credential Access",
            "techniques" => ["T1003", "T1555"],
            "threshold" => 1,
            "timeframe" => 1800,
            "description" => "Credential dumping or password store access"
          },
          %{
            "name" => "File Discovery",
            "techniques" => ["T1083", "T1039"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Search for sensitive documents"
          },
          %{
            "name" => "Data Staging",
            "techniques" => ["T1074", "T1560"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_agent" => true},
            "description" => "Archive or compress collected data"
          },
          %{
            "name" => "Exfiltration",
            "techniques" => ["T1041", "T1048", "T1567"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "Transfer data out of network"
          }
        ],
        "narrative_template" =>
          "Data theft operation: user {user} collected credentials, staged sensitive files, and exfiltrated to {source_ip} over {timespan}"
      }
    }
  end

  defp insider_threat_chain do
    %{
      name: "Insider Threat Pattern",
      description: "Suspicious data access and exfiltration by authorized user",
      severity: "medium",
      author: "Tamandua EDR",
      tags: ["insider-threat", "data-loss"],
      definition: %{
        "steps" => [
          %{
            "name" => "Unusual File Access",
            "techniques" => ["T1005", "T1039"],
            "threshold" => 3,
            "timeframe" => 1800,
            "description" => "Access to sensitive files outside normal hours"
          },
          %{
            "name" => "Data Collection",
            "techniques" => ["T1074", "T1560"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Large volume of files archived"
          },
          %{
            "name" => "Exfiltration",
            "techniques" => ["T1052", "T1567"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Data copied to removable media or cloud"
          }
        ],
        "narrative_template" =>
          "Insider threat detected: user {user} accessed {count} sensitive files and attempted exfiltration within {timespan}"
      }
    }
  end

  defp web_shell_deployment_chain do
    %{
      name: "Web Shell Deployment and Exploitation",
      description: "Web application compromise leading to shell access",
      severity: "critical",
      author: "Tamandua EDR",
      tags: ["initial-access", "persistence", "web-attack"],
      definition: %{
        "steps" => [
          %{
            "name" => "Web Application Exploit",
            "techniques" => ["T1190"],
            "threshold" => 1,
            "timeframe" => 900,
            "description" => "Exploitation of public-facing application"
          },
          %{
            "name" => "Web Shell Upload",
            "techniques" => ["T1505.003"],
            "threshold" => 1,
            "timeframe" => 600,
            "conditions" => %{"same_dest_ip" => true},
            "description" => "Web shell file written to disk"
          },
          %{
            "name" => "Command Execution",
            "techniques" => ["T1059", "T1059.003", "T1059.004"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_agent" => true},
            "description" => "Commands executed via web shell"
          }
        ],
        "narrative_template" =>
          "Web shell attack: application exploited and shell deployed on {source_ip}, executing commands as {user} within {timespan}"
      }
    }
  end

  defp supply_chain_attack_chain do
    %{
      name: "Supply Chain Compromise Pattern",
      description: "Detection of supply chain attack indicators",
      severity: "critical",
      author: "Tamandua EDR",
      tags: ["supply-chain", "initial-access"],
      definition: %{
        "steps" => [
          %{
            "name" => "Compromised Software Installation",
            "techniques" => ["T1195", "T1195.002"],
            "threshold" => 1,
            "timeframe" => 3600,
            "description" => "Installation of compromised software package"
          },
          %{
            "name" => "Unexpected Network Activity",
            "techniques" => ["T1071", "T1105"],
            "threshold" => 1,
            "timeframe" => 1800,
            "conditions" => %{"same_process" => true},
            "description" => "Outbound connection from trusted application"
          },
          %{
            "name" => "Execution or Persistence",
            "techniques" => ["T1059", "T1053", "T1547"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_agent" => true},
            "description" => "Malicious payload deployed"
          }
        ],
        "narrative_template" =>
          "Supply chain attack detected: compromised software {process} made unexpected network connections and deployed payload within {timespan}"
      }
    }
  end

  defp cloud_credential_theft_chain do
    %{
      name: "Cloud Credential Theft",
      description: "Cloud credential harvesting and abuse",
      severity: "high",
      author: "Tamandua EDR",
      tags: ["cloud", "credential-access"],
      definition: %{
        "steps" => [
          %{
            "name" => "Credential Discovery",
            "techniques" => ["T1552", "T1552.001"],
            "threshold" => 1,
            "timeframe" => 1800,
            "description" => "Search for cloud credentials or tokens"
          },
          %{
            "name" => "Cloud API Access",
            "techniques" => ["T1078.004"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Unusual cloud API calls with stolen credentials"
          },
          %{
            "name" => "Cloud Resource Access",
            "techniques" => ["T1530", "T1213"],
            "threshold" => 1,
            "timeframe" => 3600,
            "conditions" => %{"same_user" => true},
            "description" => "Access to cloud storage or repositories"
          }
        ],
        "narrative_template" =>
          "Cloud credential theft: user {user} discovered cloud credentials and accessed cloud resources from {source_ip} within {timespan}"
      }
    }
  end

  # ─────────────────────────────────────────────────────────────────────
  # Helper Functions
  # ─────────────────────────────────────────────────────────────────────

  defp install_chain(chain_def, organization_id) do
    attrs = Map.put(chain_def, :organization_id, organization_id)

    # Check if chain already exists
    existing =
      Repo.get_by(AttackChain,
        name: chain_def.name,
        organization_id: organization_id
      )

    case existing do
      nil ->
        %AttackChain{}
        |> AttackChain.changeset(attrs)
        |> Repo.insert()

      chain ->
        # Update existing chain
        chain
        |> AttackChain.changeset(attrs)
        |> Repo.update()
    end
  rescue
    e ->
      Logger.error("[ChainLibrary] Failed to install chain #{chain_def.name}: #{Exception.message(e)}")
      {:error, e}
  end

  defp create_chain_from_definition(definition, organization_id) do
    attrs = Map.put(definition, :organization_id, organization_id)

    %AttackChain{}
    |> AttackChain.changeset(attrs)
    |> Repo.insert()
  end
end
