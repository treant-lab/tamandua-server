defmodule TamanduaServer.Detection.Packs do
  @moduledoc """
  Detection Packs - Curated bundles of detection rules for specific threat categories.

  Packs can be:
  - **Built-in**: Shipped with Tamandua, free, always available
  - **Community**: Submitted by researchers, validated, free
  - **Premium**: Paid packs (future)
  - **Bounty-funded**: Funded by organizations for specific threats

  ## Available Packs

  - `web3_stealer` - Cryptocurrency wallet stealers, browser extension hijackers
  - `rto2_evasion` - Red Team Ops II evasion techniques (PPID spoofing, syscalls)
  - `ai_runtime` - AI/ML development environment threats
  - `ransomware_behavior` - Ransomware behavioral patterns
  - `lateral_movement` - Internal network spread techniques

  ## Usage

      # List available packs
      Packs.list_available()

      # Get pack details
      {:ok, pack} = Packs.get_pack("web3_stealer")

      # Install pack for organization
      {:ok, installed} = Packs.install_pack("web3_stealer", org_id)

      # List installed packs
      Packs.list_installed(org_id)
  """

  require Logger

  alias TamanduaServer.Repo
  alias TamanduaServer.Detection
  alias TamanduaServer.Detection.{RuleValidator, SigmaRule, YaraRule}

  import Ecto.Query

  # Built-in packs shipped with Tamandua
  @built_in_packs %{
    "web3_stealer" => %{
      id: "web3_stealer",
      name: "Web3 Stealer Pack",
      description: "Comprehensive detection for cryptocurrency wallet stealers including Lumma, Vidar, RedLine, Raccoon. Covers MetaMask, Phantom, Solflare, Backpack and other Web3 wallets. Includes session hijacking, clipboard monitoring, and C2 detection.",
      version: "2.0.0",
      category: "credential_access",
      tier: :free,
      creator_wallet: nil,
      mitre_techniques: ["T1555.003", "T1539", "T1528", "T1056.001", "T1115", "T1552.001"],
      rules: [
        %{
          id: "sigma_chrome_wallet_access",
          type: "sigma",
          name: "Browser Credential and Wallet Data Access",
          path: "priv/sigma_rules/credential_access/browser_credential_theft.yml"
        },
        %{
          id: "sigma_crypto_wallet_theft",
          type: "sigma",
          name: "Crypto Wallet Extension Theft",
          path: "priv/sigma_rules/credential_access/crypto_wallet_theft.yml"
        },
        %{
          id: "sigma_credential_manager_access",
          type: "sigma",
          name: "Credential Manager Access",
          path: "priv/sigma_rules/credential_access/credential_manager_access.yml"
        },
        %{
          id: "yara_credential_theft",
          type: "yara",
          name: "Credential Theft String Patterns",
          path: "priv/yara_rules/credential_theft.yar"
        },
        %{
          id: "yara_infostealers_crypto",
          type: "yara",
          name: "Infostealer Families (Lumma, Vidar, RedLine, Raccoon)",
          path: "priv/yara_rules/infostealers_crypto.yar"
        }
      ],
      tags: ["web3", "crypto", "stealer", "wallet", "defi", "lumma", "vidar", "redline", "solana", "ethereum"],
      threat_actors: ["Lazarus", "BlueNoroff", "Kimsuky", "LummaC2", "RedLine Team"],
      install_count: 0,
      rating: 4.9,
      verified: true
    },
    "rto2_evasion" => %{
      id: "rto2_evasion",
      name: "RTO II Evasion Pack",
      description: "Advanced evasion technique detection covering Red Team Ops Level 2: PPID spoofing, indirect syscalls, command line spoofing, ETW bypass, and more.",
      version: "1.0.0",
      category: "defense_evasion",
      tier: :free,
      creator_wallet: nil,
      mitre_techniques: ["T1134.004", "T1564.010", "T1562.006", "T1055"],
      rules: [
        %{
          id: "sigma_ppid_spoofing",
          type: "sigma",
          name: "PPID Spoofing Detection",
          path: "priv/sigma_rules/defense_evasion/ppid_spoofing.yml"
        },
        %{
          id: "sigma_cmdline_spoofing",
          type: "sigma",
          name: "Command Line Spoofing",
          path: "priv/sigma_rules/defense_evasion/command_line_spoofing.yml"
        },
        %{
          id: "yara_indirect_syscalls",
          type: "yara",
          name: "Indirect Syscall Patterns",
          path: "priv/yara_rules/indirect_syscalls.yar"
        }
      ],
      tags: ["evasion", "rto", "redteam", "advanced", "syscall"],
      threat_actors: ["APT29", "FIN7", "Cobalt Group"],
      install_count: 0,
      rating: 4.9,
      verified: true
    },
    "ai_runtime" => %{
      id: "ai_runtime",
      name: "AI Runtime Security Pack",
      description: "Security monitoring for AI/ML development environments: model theft, training data exfiltration, malicious AI devtool configs, MCP abuse, and agent skill/prompt attacks.",
      version: "1.1.0",
      category: "collection",
      tier: :free,
      creator_wallet: nil,
      mitre_techniques: [
        "T1005",
        "T1074",
        "T1560",
        "T1020",
        "T1041",
        "T1059",
        "T1552.001",
        "T1562"
      ],
      rules: [
        %{
          id: "sigma_model_exfil",
          type: "sigma",
          name: "AI Runtime Data Exfiltration",
          path: "priv/sigma_rules/ai_runtime/data_exfiltration.yml"
        },
        %{
          id: "sigma_prompt_injection",
          type: "sigma",
          name: "Prompt Injection Patterns",
          path: "priv/sigma_rules/ai_runtime/prompt_injection.yml"
        },
        %{
          id: "sigma_mcp_tool_abuse",
          type: "sigma",
          name: "MCP Tool Abuse",
          path: "priv/sigma_rules/ai_runtime/mcp_tool_abuse.yml"
        },
        %{
          id: "sigma_ai_devtool_artifacts",
          type: "sigma",
          name: "AI Devtool and Skill Artifact Abuse",
          path: "priv/sigma_rules/ai_runtime/devtool_artifact_abuse.yml"
        }
      ],
      tags: [
        "ai",
        "ml",
        "jupyter",
        "model",
        "training",
        "codex",
        "claude",
        "cursor",
        "windsurf",
        "mcp",
        "skills"
      ],
      threat_actors: [],
      install_count: 0,
      rating: 4.6,
      verified: true
    },
    "ransomware_behavior" => %{
      id: "ransomware_behavior",
      name: "Ransomware Behavior Pack",
      description: "Behavioral detection of ransomware activity: mass file encryption, shadow copy deletion, ransom note creation, recovery inhibition.",
      version: "1.0.0",
      category: "impact",
      tier: :free,
      creator_wallet: nil,
      mitre_techniques: ["T1486", "T1490", "T1489", "T1491"],
      rules: [
        %{
          id: "sigma_vss_deletion",
          type: "sigma",
          name: "Ransomware Indicators",
          path: "priv/sigma_rules/impact/ransomware_indicators.yml"
        },
        %{
          id: "sigma_data_destruction",
          type: "sigma",
          name: "Data Destruction",
          path: "priv/sigma_rules/impact/data_destruction.yml"
        },
        %{
          id: "yara_ransom_note",
          type: "yara",
          name: "Ransom Note Patterns",
          path: "priv/yara_rules/ransomware.yar"
        }
      ],
      tags: ["ransomware", "encryption", "impact", "recovery"],
      threat_actors: ["LockBit", "BlackCat", "Cl0p", "Play"],
      install_count: 0,
      rating: 4.9,
      verified: true
    },
    "lateral_movement" => %{
      id: "lateral_movement",
      name: "Lateral Movement Pack",
      description: "Detection of internal network spread techniques: SMB lateral movement, WMI execution, PsExec, WinRM abuse, RDP tunneling.",
      version: "1.0.0",
      category: "lateral_movement",
      tier: :free,
      creator_wallet: nil,
      mitre_techniques: ["T1021.002", "T1021.006", "T1047", "T1570", "T1021.001"],
      rules: [
        %{
          id: "sigma_smb_lateral",
          type: "sigma",
          name: "SMB Lateral Movement",
          path: "priv/sigma_rules/lateral_movement/smb_lateral.yml"
        },
        %{
          id: "sigma_wmi_remote",
          type: "sigma",
          name: "WMI Remote Execution",
          path: "priv/sigma_rules/lateral_movement/wmi_lateral.yml"
        },
        %{
          id: "sigma_psexec",
          type: "sigma",
          name: "PsExec Usage",
          path: "priv/sigma_rules/lateral_movement/psexec_usage.yml"
        }
      ],
      tags: ["lateral", "smb", "wmi", "psexec", "network"],
      threat_actors: ["APT28", "APT29", "FIN6"],
      install_count: 0,
      rating: 4.7,
      verified: true
    }
  }

  # Schema for installed packs (stored in DB)
  defmodule InstalledPack do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id

    schema "installed_packs" do
      field :pack_id, :string
      field :pack_version, :string
      field :organization_id, :binary_id
      field :installed_by_id, :binary_id
      field :enabled, :boolean, default: true
      field :config, :map, default: %{}

      timestamps()
    end

    def changeset(installed, attrs) do
      installed
      |> cast(attrs, [:pack_id, :pack_version, :organization_id, :installed_by_id, :enabled, :config])
      |> validate_required([:pack_id, :pack_version, :organization_id])
      |> unique_constraint([:pack_id, :organization_id])
    end
  end

  @doc """
  List all available packs (built-in + community).
  """
  @spec list_available() :: [map()]
  def list_available do
    @built_in_packs
    |> Map.values()
    |> Enum.map(&with_rule_availability/1)
    |> Enum.sort_by(& &1.rating, :desc)
  end

  @doc """
  Get a specific pack by ID.
  """
  @spec get_pack(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get_pack(pack_id) do
    case Map.get(@built_in_packs, pack_id) do
      nil -> {:error, :not_found}
      pack -> {:ok, with_rule_availability(pack)}
    end
  end

  @doc """
  List packs installed for an organization.
  """
  @spec list_installed(String.t()) :: [map()]
  def list_installed(organization_id) do
    from(ip in InstalledPack,
      where: ip.organization_id == ^organization_id,
      order_by: [desc: ip.inserted_at]
    )
    |> Repo.all()
    |> Enum.map(fn installed ->
      case get_pack(installed.pack_id) do
        {:ok, pack} -> Map.merge(pack, %{installed: installed_info(installed), enabled: installed.enabled})
        _ -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  @doc """
  Install a pack for an organization.
  """
  @spec install_pack(String.t(), String.t(), keyword()) :: {:ok, InstalledPack.t()} | {:error, term()}
  def install_pack(pack_id, organization_id, opts \\ []) do
    installed_by_id = Keyword.get(opts, :installed_by_id)

    with {:ok, pack} <- get_pack(pack_id),
         {:ok, _} <- check_not_installed(pack_id, organization_id) do
      %InstalledPack{}
      |> InstalledPack.changeset(%{
        pack_id: pack_id,
        pack_version: pack.version,
        organization_id: organization_id,
        installed_by_id: installed_by_id,
        enabled: false,
        config: %{"activation_status" => "pending"}
      })
      |> Repo.insert()
      |> case do
        {:ok, installed} ->
          activation = activate_pack_rules(pack, organization_id)
          enabled = activation.rules_enabled > 0

          installed
          |> InstalledPack.changeset(%{
            enabled: enabled,
            config: activation_config(activation)
          })
          |> Repo.update()
          |> case do
            {:ok, updated} ->
              Logger.info(
                "[Packs] Pack installed: #{pack_id} for org #{organization_id}; " <>
                  "#{activation.rules_enabled}/#{activation.rules_available} rules enabled"
              )

              {:ok, updated}

            error ->
              error
          end

        error ->
          error
      end
    end
  end

  @doc """
  Uninstall a pack from an organization.
  """
  @spec uninstall_pack(String.t(), String.t()) :: {:ok, InstalledPack.t()} | {:error, term()}
  def uninstall_pack(pack_id, organization_id) do
    case get_installed(pack_id, organization_id) do
      nil ->
        {:error, :not_installed}

      installed ->
        with {:ok, pack} <- get_pack(pack_id),
             activation <- deactivate_pack_rules(pack, organization_id),
             true <- activation.rules_enabled == 0 || {:error, {:deactivation_failed, activation}} do
          Repo.delete(installed)
        end
    end
  end

  @doc """
  Enable or disable a pack for an organization.
  """
  @spec set_enabled(String.t(), String.t(), boolean()) :: {:ok, InstalledPack.t()} | {:error, term()}
  def set_enabled(pack_id, organization_id, enabled) do
    case get_installed(pack_id, organization_id) do
      nil ->
        {:error, :not_installed}

      installed ->
        with {:ok, pack} <- get_pack(pack_id) do
          activation =
            if enabled do
              activate_pack_rules(pack, organization_id)
            else
              deactivate_pack_rules(pack, organization_id)
            end

          enabled = activation.rules_enabled > 0

          installed
          |> InstalledPack.changeset(%{enabled: enabled, config: activation_config(activation)})
          |> Repo.update()
        end
    end
  end

  @doc """
  Get pack statistics for an organization.
  """
  @spec get_stats(String.t()) :: map()
  def get_stats(nil) do
    %{
      total_available: map_size(@built_in_packs),
      total_installed: 0,
      enabled_count: 0,
      techniques_covered: 0,
      rules_available: 0,
      rules_enabled: 0,
      rules_active: 0
    }
  end

  def get_stats(organization_id) do
    installed = list_installed(organization_id)

    rules_available = Enum.reduce(installed, 0, &(&1.rules_available + &2))
    rules_enabled = Enum.reduce(installed, 0, &(enabled_rule_count(&1, organization_id) + &2))

    %{
      total_available: map_size(@built_in_packs),
      total_installed: length(installed),
      enabled_count: Enum.count(installed, & &1.enabled),
      techniques_covered:
        installed
        |> Enum.filter(& &1.enabled)
        |> Enum.flat_map(& &1.mitre_techniques)
        |> Enum.uniq()
        |> length(),
      rules_available: rules_available,
      rules_enabled: rules_enabled,
      rules_active: rules_enabled
    }
  end

  @doc """
  Get packs by category.
  """
  @spec list_by_category(String.t()) :: [map()]
  def list_by_category(category) do
    list_available()
    |> Enum.filter(&(&1.category == category))
  end

  @doc """
  Search packs by tag or name.
  """
  @spec search(String.t()) :: [map()]
  def search(query) do
    query_lower = String.downcase(query)

    list_available()
    |> Enum.filter(fn pack ->
      String.contains?(String.downcase(pack.name), query_lower) or
      String.contains?(String.downcase(pack.description), query_lower) or
      Enum.any?(pack.tags, &String.contains?(&1, query_lower))
    end)
  end

  # Private helpers

  defp check_not_installed(pack_id, organization_id) do
    case get_installed(pack_id, organization_id) do
      nil -> {:ok, :not_installed}
      _ -> {:error, :already_installed}
    end
  end

  defp get_installed(pack_id, organization_id) do
    Repo.one(
      from ip in InstalledPack,
        where: ip.pack_id == ^pack_id,
        where: ip.organization_id == ^organization_id
    )
  end

  defp activate_pack_rules(pack, organization_id) do
    sync_pack_rules(pack, organization_id, true)
  end

  defp deactivate_pack_rules(pack, organization_id) do
    sync_pack_rules(pack, organization_id, false)
  end

  defp sync_pack_rules(pack, organization_id, enabled) do
    initial = %{
      activation_status: if(enabled, do: "enabled", else: "disabled"),
      rules_available: count_available_rule_files(pack),
      rules_enabled: 0,
      rules_imported: 0,
      rules_updated: 0,
      rules_missing: missing_rule_ids(pack),
      rules_failed: []
    }

    pack.rules
    |> Enum.reduce(initial, fn rule, acc ->
      case sync_pack_rule(pack, rule, organization_id, enabled) do
        {:ok, :disabled} ->
          %{acc | rules_updated: acc.rules_updated + 1}

        {:ok, :imported} ->
          %{acc |
            rules_enabled: acc.rules_enabled + enabled_rule_count(enabled),
            rules_imported: acc.rules_imported + 1
          }

        {:ok, :updated} ->
          %{acc |
            rules_enabled: acc.rules_enabled + enabled_rule_count(enabled),
            rules_updated: acc.rules_updated + 1
          }

        {:error, :missing} ->
          acc

        {:error, reason} ->
          %{acc | rules_failed: [%{id: rule.id, reason: inspect(reason)} | acc.rules_failed]}
      end
    end)
    |> Map.put(:rules_enabled, enabled_rule_count(pack, organization_id))
    |> finalize_activation_status(enabled)
  end

  defp sync_pack_rule(pack, rule, organization_id, false) do
    case get_pack_rule_record(rule.type, pack.id, rule.id, organization_id) do
      nil -> {:ok, :disabled}
      record -> update_pack_rule_record(record, rule.type, %{enabled: false})
    end
  end

  defp sync_pack_rule(pack, rule, organization_id, true) do
    full_path = resolve_pack_path(rule.path)

    with true <- File.exists?(full_path) || {:error, :missing},
         {:ok, source} <- File.read(full_path),
         {:ok, attrs} <- attrs_from_rule_source(rule.type, source) do
      attrs =
        attrs
        |> Map.put(:name, pack_rule_name(pack.id, rule.id))
        |> Map.put(:organization_id, organization_id)
        |> Map.put(:enabled, true)
        |> Map.update(
          :tags,
          pack_rule_tags(pack.id, rule.id),
          &Enum.uniq(&1 ++ pack_rule_tags(pack.id, rule.id))
        )

      upsert_pack_rule_record(rule.type, pack.id, rule.id, organization_id, attrs)
    end
  end

  defp attrs_from_rule_source("sigma", source) do
    RuleValidator.validate_sigma(source)
  end

  defp attrs_from_rule_source("yara", source) do
    with {:ok, metadata} <- RuleValidator.validate_yara(source) do
      {:ok,
       %{
         description: metadata.description,
         author: metadata.author,
         source: source,
         tags: metadata.tags,
         severity: "medium"
       }}
    end
  end

  defp attrs_from_rule_source(type, _source), do: {:error, "unsupported rule type #{type}"}

  defp upsert_pack_rule_record("sigma", pack_id, rule_id, organization_id, attrs) do
    case get_pack_rule_record("sigma", pack_id, rule_id, organization_id) do
      nil ->
        case Detection.create_sigma_rule(attrs) do
          {:ok, _rule} -> {:ok, :imported}
          error -> error
        end

      %SigmaRule{} = rule ->
        case Detection.update_sigma_rule(rule, attrs) do
          {:ok, _rule} -> {:ok, :updated}
          error -> error
        end
    end
  end

  defp upsert_pack_rule_record("yara", pack_id, rule_id, organization_id, attrs) do
    case get_pack_rule_record("yara", pack_id, rule_id, organization_id) do
      nil ->
        case Detection.create_yara_rule(attrs) do
          {:ok, _rule} -> {:ok, :imported}
          error -> error
        end

      %YaraRule{} = rule ->
        case Detection.update_yara_rule(rule, attrs) do
          {:ok, _rule} -> {:ok, :updated}
          error -> error
        end
    end
  end

  defp update_pack_rule_record(%SigmaRule{} = rule, "sigma", attrs) do
    case Detection.update_sigma_rule(rule, attrs) do
      {:ok, _rule} -> {:ok, :disabled}
      error -> error
    end
  end

  defp update_pack_rule_record(%YaraRule{} = rule, "yara", attrs) do
    case Detection.update_yara_rule(rule, attrs) do
      {:ok, _rule} -> {:ok, :disabled}
      error -> error
    end
  end

  defp get_pack_rule_record("sigma", pack_id, rule_id, organization_id) do
    Repo.get_by(SigmaRule, name: pack_rule_name(pack_id, rule_id), organization_id: organization_id)
  end

  defp get_pack_rule_record("yara", pack_id, rule_id, organization_id) do
    Repo.get_by(YaraRule, name: pack_rule_name(pack_id, rule_id), organization_id: organization_id)
  end

  defp enabled_rule_count(true), do: 1
  defp enabled_rule_count(false), do: 0

  defp enabled_rule_count(pack, organization_id) do
    Enum.count(pack.rules, fn rule ->
      case get_pack_rule_record(rule.type, pack.id, rule.id, organization_id) do
        nil -> false
        record -> record.enabled
      end
    end)
  end

  defp finalize_activation_status(%{rules_enabled: 0} = stats, false) do
    %{stats | activation_status: "disabled"}
  end

  defp finalize_activation_status(stats, false) do
    %{stats | activation_status: "disable_failed"}
  end

  defp finalize_activation_status(%{rules_enabled: 0, rules_available: 0} = stats, true) do
    %{stats | activation_status: "no_rules_available"}
  end

  defp finalize_activation_status(%{rules_enabled: 0} = stats, true) do
    %{stats | activation_status: "no_rules_enabled"}
  end

  defp finalize_activation_status(%{rules_enabled: enabled, rules_available: available} = stats, true)
       when enabled == available do
    %{stats | activation_status: "enabled"}
  end

  defp finalize_activation_status(stats, true) do
    %{stats | activation_status: "partially_enabled"}
  end

  defp activation_config(stats) do
    %{
      activation_status: stats.activation_status,
      rules_available: stats.rules_available,
      rules_enabled: stats.rules_enabled,
      rules_imported: stats.rules_imported,
      rules_updated: stats.rules_updated,
      rules_missing: stats.rules_missing,
      rules_failed: Enum.reverse(stats.rules_failed)
    }
  end

  defp with_rule_availability(pack) do
    rules =
      Enum.map(pack.rules, fn rule ->
        Map.put(rule, :available, File.exists?(resolve_pack_path(rule.path)))
      end)

    pack
    |> Map.put(:rules, rules)
    |> Map.put(:rules_available, Enum.count(rules, & &1.available))
    |> Map.put(:rules_missing, rules |> Enum.reject(& &1.available) |> Enum.map(& &1.id))
  end

  defp count_available_rule_files(pack) do
    Enum.count(pack.rules, &File.exists?(resolve_pack_path(&1.path)))
  end

  defp missing_rule_ids(pack) do
    pack.rules
    |> Enum.reject(&File.exists?(resolve_pack_path(&1.path)))
    |> Enum.map(& &1.id)
  end

  defp installed_info(installed) do
    %{
      id: installed.id,
      enabled: installed.enabled,
      installed_at: installed.inserted_at,
      config: installed.config || %{}
    }
  end

  defp pack_rule_name(pack_id, rule_id), do: "pack_#{pack_id}_#{rule_id}"

  defp pack_rule_tags(pack_id, rule_id) do
    ["detection_pack", "pack:#{pack_id}", "pack_rule:#{rule_id}"]
  end

  defp resolve_pack_path("priv/" <> relative_path) do
    case :code.priv_dir(:tamandua_server) do
      {:error, _} ->
        Path.join(["apps", "tamandua_server", "priv", relative_path])

      priv_dir ->
        priv_dir
        |> to_string()
        |> Path.join(relative_path)
    end
  end

  defp resolve_pack_path(path), do: path
end
