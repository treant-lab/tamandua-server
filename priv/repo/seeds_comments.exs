# Seed data for testing the commenting system
#
# Run with:
#   mix run priv/repo/seeds_comments.exs

alias TamanduaServer.Repo
alias TamanduaServer.Accounts.{Organization, User}
alias TamanduaServer.Agents.Agent
alias TamanduaServer.Alerts.{Alert, CommentManager}

import Ecto.Query

# Get or create test organization
org =
  Repo.one(from o in Organization, where: o.slug == "test-org", limit: 1) ||
    Repo.insert!(%Organization{
      name: "Test Organization",
      slug: "test-org"
    })

IO.puts("Using organization: #{org.name}")

# Create test users
users = [
  %{
    email: "alice@test.com",
    name: "Alice Anderson",
    role: "admin",
    password_hash: Bcrypt.hash_pwd_salt("password123")
  },
  %{
    email: "bob@test.com",
    name: "Bob Baker",
    role: "analyst",
    password_hash: Bcrypt.hash_pwd_salt("password123")
  },
  %{
    email: "charlie@test.com",
    name: "Charlie Chen",
    role: "analyst",
    password_hash: Bcrypt.hash_pwd_salt("password123")
  },
  %{
    email: "diana@test.com",
    name: "Diana Davis",
    role: "responder",
    password_hash: Bcrypt.hash_pwd_salt("password123")
  }
]

test_users =
  Enum.map(users, fn user_data ->
    Repo.one(from u in User, where: u.email == ^user_data.email, limit: 1) ||
      Repo.insert!(%User{
        email: user_data.email,
        name: user_data.name,
        role: user_data.role,
        password_hash: user_data.password_hash,
        organization_id: org.id
      })
  end)

[alice, bob, charlie, diana] = test_users
IO.puts("Created/found #{length(test_users)} test users")

# Create test agent
agent =
  Repo.one(from a in Agent, where: a.hostname == "test-workstation-01", limit: 1) ||
    Repo.insert!(%Agent{
      hostname: "test-workstation-01",
      os_type: "windows",
      os_version: "10.0.19044",
      organization_id: org.id
    })

IO.puts("Using agent: #{agent.hostname}")

# Create test alerts with comments
alerts = [
  %{
    title: "Suspicious PowerShell Execution Detected",
    description:
      "PowerShell was executed with encoded command flag, commonly used by attackers to obfuscate malicious scripts.",
    severity: "high",
    status: "investigating",
    threat_score: 8.5,
    mitre_tactics: ["Execution", "Defense Evasion"],
    mitre_techniques: ["T1059.001", "T1027"],
    evidence: %{
      process_name: "powershell.exe",
      command_line: "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
      parent_process: "explorer.exe",
      user: "SYSTEM"
    }
  },
  %{
    title: "Potential Credential Dumping Activity",
    description:
      "lsass.exe memory was accessed by an unusual process, indicating possible credential theft attempt.",
    severity: "critical",
    status: "new",
    threat_score: 9.2,
    mitre_tactics: ["Credential Access"],
    mitre_techniques: ["T1003.001"],
    evidence: %{
      process_name: "mimikatz.exe",
      target_process: "lsass.exe",
      access_rights: "PROCESS_VM_READ"
    }
  },
  %{
    title: "Suspicious Network Connection to Known C2 Server",
    description: "Outbound connection detected to IP address associated with known APT group.",
    severity: "high",
    status: "investigating",
    threat_score: 8.7,
    mitre_tactics: ["Command and Control"],
    mitre_techniques: ["T1071.001"],
    evidence: %{
      destination_ip: "185.220.101.45",
      destination_port: 443,
      process_name: "svchost.exe",
      bytes_sent: 12_458,
      bytes_received: 89_234
    }
  }
]

created_alerts =
  Enum.map(alerts, fn alert_data ->
    Repo.insert!(%Alert{
      title: alert_data.title,
      description: alert_data.description,
      severity: alert_data.severity,
      status: alert_data.status,
      threat_score: alert_data.threat_score,
      mitre_tactics: alert_data.mitre_tactics,
      mitre_techniques: alert_data.mitre_techniques,
      evidence: alert_data.evidence,
      organization_id: org.id,
      agent_id: agent.id
    })
  end)

IO.puts("Created #{length(created_alerts)} test alerts")

# Add comments to first alert
[alert1, alert2, alert3] = created_alerts

# Alert 1: Rich discussion with threading
{:ok, comment1} =
  CommentManager.create_comment(
    %{
      "content" => """
      I've analyzed the encoded PowerShell command. After decoding, it appears to be downloading a payload from:
      `hxxp://malicious-site[.]com/payload.exe`

      This matches known IOCs for the **TrickBot** malware family.

      Recommended actions:
      1. Isolate the endpoint immediately
      2. Collect memory dump
      3. Check for persistence mechanisms
      """
    },
    bob,
    alert1
  )

IO.puts("Created comment 1")

# Reply to comment 1
{:ok, reply1} =
  CommentManager.create_comment(
    %{
      "content" => "Good catch @bob.baker! I'm isolating the host now.",
      "parent_id" => comment1.id
    },
    diana,
    alert1
  )

IO.puts("Created reply 1")

# Another reply
{:ok, reply2} =
  CommentManager.create_comment(
    %{
      "content" =>
        "Memory dump collected. Uploading to VirusTotal for analysis. ETA 5 minutes.",
      "parent_id" => comment1.id
    },
    diana,
    alert1
  )

IO.puts("Created reply 2")

# Second top-level comment
{:ok, comment2} =
  CommentManager.create_comment(
    %{
      "content" => """
      Cross-referencing with our threat intel feeds:

      - IP `185.220.101.45` is listed in **Abuse.ch** as active C2
      - Domain first seen: 2024-12-15
      - Associated with TrickBot campaign targeting financial sector

      This is a **confirmed true positive**.
      """
    },
    charlie,
    alert1
  )

IO.puts("Created comment 2")

# Pin important comment (as admin)
{:ok, _} = CommentManager.toggle_pin(comment2, alice)
IO.puts("Pinned comment 2")

# Add reactions
{:ok, _} = CommentManager.toggle_reaction(comment1, "thumbs_up", alice)
{:ok, _} = CommentManager.toggle_reaction(comment1, "thumbs_up", charlie)
{:ok, _} = CommentManager.toggle_reaction(comment1, "eyes", diana)
{:ok, _} = CommentManager.toggle_reaction(comment2, "rocket", bob)
{:ok, _} = CommentManager.toggle_reaction(comment2, "check", alice)

IO.puts("Added reactions")

# Edit a comment
{:ok, _} =
  CommentManager.edit_comment(
    comment1,
    %{
      "content" => """
      I've analyzed the encoded PowerShell command. After decoding, it appears to be downloading a payload from:
      `hxxp://malicious-site[.]com/payload.exe`

      This matches known IOCs for the **TrickBot** malware family.

      **UPDATE**: VirusTotal results confirm 45/72 AV vendors detect this as TrickBot.

      Recommended actions:
      1. Isolate the endpoint immediately ✅ (DONE)
      2. Collect memory dump ✅ (DONE)
      3. Check for persistence mechanisms
      4. Scan all endpoints for similar IOCs
      """
    },
    bob
  )

IO.puts("Edited comment 1")

# Alert 2: Credential dumping discussion
{:ok, comment3} =
  CommentManager.create_comment(
    %{
      "content" => """
      **CRITICAL**: This is active credential dumping!

      The process `mimikatz.exe` is a well-known tool for extracting credentials from memory.

      Immediate actions required:
      - [ ] Force password reset for all users on this system
      - [ ] Review authentication logs for lateral movement
      - [ ] Check for unauthorized access attempts
      """
    },
    alice,
    alert2
  )

{:ok, _} = CommentManager.toggle_pin(comment3, alice)

{:ok, _} =
  CommentManager.create_comment(
    %{
      "content" =>
        "Password resets initiated. Monitoring authentication logs for suspicious activity.",
      "parent_id" => comment3.id
    },
    diana,
    alert2
  )

IO.puts("Created comments for alert 2")

# Alert 3: Network connection analysis
{:ok, comment4} =
  CommentManager.create_comment(
    %{
      "content" => """
      Checking OSINT sources for this IP:

      **185.220.101.45**
      - AbuseIPDB score: 100/100 (reported 1,247 times)
      - First seen: 2023-06-12
      - ASN: AS60068 (CDN77)
      - Country: Czech Republic

      This is definitely malicious. Adding to our IOC blocklist.
      """
    },
    charlie,
    alert3
  )

{:ok, _} =
  CommentManager.create_comment(
    %{
      "content" =>
        "@charlie.chen Thanks for the analysis. I've blocked this IP at the firewall level.",
      "parent_id" => comment4.id
    },
    bob,
    alert3
  )

{:ok, _} = CommentManager.toggle_reaction(comment4, "thumbs_up", alice)
{:ok, _} = CommentManager.toggle_reaction(comment4, "thumbs_up", bob)

IO.puts("Created comments for alert 3")

# Summary
IO.puts("\n=== Seed Data Summary ===")
IO.puts("Organization: #{org.name}")
IO.puts("Users: #{length(test_users)}")
IO.puts("Agent: #{agent.hostname}")
IO.puts("Alerts: #{length(created_alerts)}")
IO.puts("\nYou can now:")
IO.puts("1. Login as alice@test.com / password123 (admin)")
IO.puts("2. Login as bob@test.com / password123 (analyst)")
IO.puts("3. Login as charlie@test.com / password123 (analyst)")
IO.puts("4. Login as diana@test.com / password123 (responder)")
IO.puts("\nNavigate to /alerts to see the test alerts with comments!")
IO.puts("========================\n")
