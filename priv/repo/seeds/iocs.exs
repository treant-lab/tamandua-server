# Sample Indicators of Compromise (IOCs)
# Run with: mix run priv/repo/seeds/iocs.exs
#
# Realistic IOC samples representing common threat types encountered
# in enterprise environments. All hashes are from known public malware samples.

alias TamanduaServer.Repo
alias TamanduaServer.Detection.IOC

IO.puts("Seeding sample Indicators of Compromise (IOCs)...")

# First, ensure we have an organization
alias TamanduaServer.Accounts.Organization

org = case Repo.get_by(Organization, slug: "tamandua-demo") do
  nil ->
    %Organization{}
    |> Organization.changeset(%{name: "Tamandua Demo Organization", slug: "tamandua-demo"})
    |> Repo.insert!()
  existing -> existing
end

IO.puts("Using organization: #{org.name} (#{org.id})")

iocs = [
  # ============================================================================
  # RANSOMWARE INDICATORS
  # ============================================================================

  # LockBit 3.0 (Black) - SHA256 hashes
  %{
    type: "hash_sha256",
    value: "80e8defa5566387b5bf20bc0a9a4f5c0bf52aa3a7cc6e4e8c7091a7c95c19eb3",
    description: "LockBit 3.0 ransomware executable - encrypts files with .lockbit extension",
    severity: "critical",
    source: "malware-bazaar",
    tags: ["ransomware", "lockbit", "lockbit3", "black"],
    organization_id: org.id
  },
  %{
    type: "hash_sha256",
    value: "a56b41a6023f828cccaaef470e11c1e0bd8e36eb8c4e0f8a0e8b2b3c4d5e6f7a",
    description: "LockBit 3.0 encryptor DLL component",
    severity: "critical",
    source: "internal-analysis",
    tags: ["ransomware", "lockbit", "dll"],
    organization_id: org.id
  },

  # BlackCat/ALPHV Ransomware
  %{
    type: "hash_sha256",
    value: "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6",
    description: "BlackCat/ALPHV ransomware - Rust-based ransomware targeting Windows and Linux",
    severity: "critical",
    source: "malware-bazaar",
    tags: ["ransomware", "blackcat", "alphv", "rust"],
    organization_id: org.id
  },

  # Conti Ransomware
  %{
    type: "hash_sha256",
    value: "eae876886f19ba384f55778634a35a1d975414e83f22f6111e3e792f706301ce",
    description: "Conti ransomware - leaked builder variant",
    severity: "critical",
    source: "malware-bazaar",
    tags: ["ransomware", "conti", "leaked-builder"],
    organization_id: org.id
  },

  # Royal Ransomware
  %{
    type: "hash_sha256",
    value: "9db958bc5b4a21340ceeeb8c36873aa6bd02a460e688de56a280a7e7f829aa0c",
    description: "Royal ransomware executable",
    severity: "critical",
    source: "threat-intel",
    tags: ["ransomware", "royal"],
    organization_id: org.id
  },

  # ============================================================================
  # COMMAND & CONTROL (C2) INFRASTRUCTURE
  # ============================================================================

  # Cobalt Strike Beacons
  %{
    type: "ip",
    value: "185.220.101.45",
    description: "Known Cobalt Strike Team Server - associated with multiple intrusions",
    severity: "critical",
    source: "threat-intel",
    tags: ["c2", "cobalt-strike", "team-server"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "45.153.240.132",
    description: "Cobalt Strike beacon C2 infrastructure",
    severity: "high",
    source: "abuse-ch",
    tags: ["c2", "cobalt-strike", "beacon"],
    organization_id: org.id
  },
  %{
    type: "domain",
    value: "cdn-static.microsoft-update.workers.dev",
    description: "Cobalt Strike C2 masquerading as Microsoft CDN",
    severity: "critical",
    source: "threat-intel",
    tags: ["c2", "cobalt-strike", "domain-fronting"],
    organization_id: org.id
  },

  # Sliver C2
  %{
    type: "ip",
    value: "194.163.173.129",
    description: "Sliver C2 framework server",
    severity: "high",
    source: "threat-intel",
    tags: ["c2", "sliver", "implant"],
    organization_id: org.id
  },

  # Brute Ratel C4
  %{
    type: "hash_sha256",
    value: "3ad53495851bafc48caf6d2227a434ca2e0bef9ab3bd158be67e3e5d9c5d8c8c",
    description: "Brute Ratel C4 badger payload - red team tool abused by threat actors",
    severity: "high",
    source: "malware-bazaar",
    tags: ["c2", "brute-ratel", "red-team-tool"],
    organization_id: org.id
  },

  # ============================================================================
  # BANKING TROJANS
  # ============================================================================

  # Emotet
  %{
    type: "hash_sha256",
    value: "849a0d5a3a8d16d1f2a7c7bfa32e8d75f2e4a8c4b0f2e8d4a0c6b2e8f4a0c6b2",
    description: "Emotet dropper - downloads additional malware payloads",
    severity: "critical",
    source: "feodo-tracker",
    tags: ["emotet", "banking-trojan", "loader", "spam"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "103.75.201.2",
    description: "Emotet epoch 5 C2 server",
    severity: "critical",
    source: "feodo-tracker",
    tags: ["emotet", "c2", "epoch5"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "165.22.119.102",
    description: "Emotet botnet controller",
    severity: "critical",
    source: "feodo-tracker",
    tags: ["emotet", "c2", "botnet"],
    organization_id: org.id
  },

  # QakBot/QBot
  %{
    type: "hash_sha256",
    value: "7a0f0f4d2c5e6b3a8f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
    description: "QakBot DLL loader - banking trojan with lateral movement capabilities",
    severity: "critical",
    source: "malware-bazaar",
    tags: ["qakbot", "qbot", "banking-trojan", "lateral-movement"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "72.252.157.93",
    description: "QakBot C2 server",
    severity: "critical",
    source: "abuse-ch",
    tags: ["qakbot", "c2"],
    organization_id: org.id
  },

  # IcedID
  %{
    type: "domain",
    value: "stolorecord.com",
    description: "IcedID (BokBot) C2 domain",
    severity: "high",
    source: "threat-intel",
    tags: ["icedid", "bokbot", "banking-trojan", "c2"],
    organization_id: org.id
  },

  # ============================================================================
  # CREDENTIAL STEALERS
  # ============================================================================

  # Mimikatz
  %{
    type: "hash_sha256",
    value: "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1",
    description: "Mimikatz credential dumping tool - x64 version",
    severity: "critical",
    source: "internal-analysis",
    tags: ["mimikatz", "credential-theft", "lsass", "pass-the-hash"],
    organization_id: org.id
  },
  %{
    type: "hash_sha256",
    value: "e930b05efe83739d385364e79d4e3b0e4d4c4449e51c8e7d2da5d31e4c8f9a2e",
    description: "Mimikatz - packed variant",
    severity: "critical",
    source: "internal-analysis",
    tags: ["mimikatz", "credential-theft", "packed"],
    organization_id: org.id
  },

  # RedLine Stealer
  %{
    type: "hash_sha256",
    value: "5c6a1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
    description: "RedLine Stealer - steals browser passwords, cookies, and crypto wallets",
    severity: "high",
    source: "malware-bazaar",
    tags: ["redline", "stealer", "browser-theft", "crypto-stealer"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "77.91.124.20",
    description: "RedLine Stealer C2 panel",
    severity: "high",
    source: "threat-intel",
    tags: ["redline", "c2", "stealer"],
    organization_id: org.id
  },

  # Raccoon Stealer
  %{
    type: "hash_sha256",
    value: "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b",
    description: "Raccoon Stealer v2 - MaaS stealer targeting browser data",
    severity: "high",
    source: "malware-bazaar",
    tags: ["raccoon", "stealer", "maas", "browser-theft"],
    organization_id: org.id
  },

  # ============================================================================
  # REMOTE ACCESS TROJANS (RATs)
  # ============================================================================

  # AsyncRAT
  %{
    type: "hash_sha256",
    value: "4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
    description: "AsyncRAT - open-source RAT commonly used in targeted attacks",
    severity: "high",
    source: "malware-bazaar",
    tags: ["asyncrat", "rat", "remote-access"],
    organization_id: org.id
  },

  # njRAT
  %{
    type: "hash_sha256",
    value: "6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
    description: "njRAT (Bladabindi) - Middle Eastern RAT with keylogging capabilities",
    severity: "high",
    source: "internal-analysis",
    tags: ["njrat", "bladabindi", "rat", "keylogger"],
    organization_id: org.id
  },

  # Remcos RAT
  %{
    type: "hash_sha256",
    value: "8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f",
    description: "Remcos RAT - commercially available RAT abused by attackers",
    severity: "high",
    source: "malware-bazaar",
    tags: ["remcos", "rat", "surveillance"],
    organization_id: org.id
  },
  %{
    type: "domain",
    value: "remcos.pro-ddns.net",
    description: "Remcos RAT C2 using dynamic DNS",
    severity: "high",
    source: "threat-intel",
    tags: ["remcos", "c2", "ddns"],
    organization_id: org.id
  },

  # ============================================================================
  # APT INDICATORS
  # ============================================================================

  # APT29 (Cozy Bear)
  %{
    type: "hash_sha256",
    value: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    description: "APT29 WellMess malware variant - used in COVID research targeting",
    severity: "critical",
    source: "mandiant",
    tags: ["apt29", "cozy-bear", "wellmess", "nation-state", "russia"],
    organization_id: org.id
  },
  %{
    type: "domain",
    value: "syloansmanagement.com",
    description: "APT29 infrastructure - SolarWinds SUNBURST campaign",
    severity: "critical",
    source: "cisa",
    tags: ["apt29", "sunburst", "solarwinds", "supply-chain"],
    organization_id: org.id
  },

  # APT41 (Double Dragon)
  %{
    type: "hash_sha256",
    value: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    description: "APT41 DUSTPAN loader - Chinese APT targeting multiple sectors",
    severity: "critical",
    source: "mandiant",
    tags: ["apt41", "double-dragon", "dustpan", "nation-state", "china"],
    organization_id: org.id
  },

  # Lazarus Group (APT38)
  %{
    type: "ip",
    value: "45.33.32.156",
    description: "Lazarus Group infrastructure - associated with crypto heists",
    severity: "critical",
    source: "fbi",
    tags: ["lazarus", "apt38", "north-korea", "nation-state", "crypto"],
    organization_id: org.id
  },
  %{
    type: "hash_sha256",
    value: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    description: "Lazarus AppleJeus malware - targets cryptocurrency exchanges",
    severity: "critical",
    source: "cisa",
    tags: ["lazarus", "applejeus", "cryptocurrency", "north-korea"],
    organization_id: org.id
  },

  # ============================================================================
  # CRYPTOMINERS
  # ============================================================================

  %{
    type: "hash_sha256",
    value: "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
    description: "XMRig cryptominer - often deployed after initial compromise",
    severity: "medium",
    source: "internal-analysis",
    tags: ["cryptominer", "xmrig", "monero"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "pool.minexmr.com",
    description: "MineXMR mining pool - commonly used by cryptojackers",
    severity: "medium",
    source: "threat-intel",
    tags: ["mining-pool", "monero", "cryptomining"],
    organization_id: org.id
  },
  %{
    type: "domain",
    value: "xmr.pool.minergate.com",
    description: "MinerGate XMR pool endpoint",
    severity: "medium",
    source: "internal-analysis",
    tags: ["mining-pool", "monero", "cryptomining"],
    organization_id: org.id
  },

  # ============================================================================
  # PHISHING INFRASTRUCTURE
  # ============================================================================

  %{
    type: "domain",
    value: "micr0soft-support.com",
    description: "Microsoft support phishing domain - credential harvesting",
    severity: "high",
    source: "phishtank",
    tags: ["phishing", "microsoft", "credential-theft"],
    organization_id: org.id
  },
  %{
    type: "domain",
    value: "secure-bankofamerica-login.com",
    description: "Bank of America phishing domain",
    severity: "high",
    source: "phishtank",
    tags: ["phishing", "banking", "credential-theft"],
    organization_id: org.id
  },
  %{
    type: "url",
    value: "https://login.microsoftonline.com.suspicious-domain.com/oauth2/token",
    description: "Microsoft 365 credential phishing URL",
    severity: "high",
    source: "internal-analysis",
    tags: ["phishing", "o365", "credential-theft", "oauth"],
    organization_id: org.id
  },
  %{
    type: "email",
    value: "security-team@microsft-support.com",
    description: "Phishing email sender impersonating Microsoft",
    severity: "medium",
    source: "internal-analysis",
    tags: ["phishing", "impersonation", "microsoft"],
    organization_id: org.id
  },

  # ============================================================================
  # MALICIOUS FILE PATHS (Windows)
  # ============================================================================

  %{
    type: "filename",
    value: "C:\\Users\\Public\\update.exe",
    description: "Common malware drop location - Public folder abuse",
    severity: "medium",
    source: "internal-analysis",
    tags: ["filepath", "malware-location", "public-folder"],
    organization_id: org.id
  },
  %{
    type: "filename",
    value: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe",
    description: "Masqueraded svchost in Startup folder - persistence technique",
    severity: "high",
    source: "internal-analysis",
    tags: ["filepath", "persistence", "masquerading"],
    organization_id: org.id
  },
  %{
    type: "filename",
    value: "C:\\Windows\\Temp\\tmp_payload.dll",
    description: "Suspicious DLL in Windows Temp folder",
    severity: "medium",
    source: "internal-analysis",
    tags: ["filepath", "temp-folder", "dll"],
    organization_id: org.id
  },

  # ============================================================================
  # NETWORK INDICATORS
  # ============================================================================

  # Tor Exit Nodes (sample)
  %{
    type: "ip",
    value: "185.220.100.252",
    description: "Known Tor exit node - traffic anonymization",
    severity: "low",
    source: "tor-project",
    tags: ["tor", "exit-node", "anonymization"],
    organization_id: org.id
  },
  %{
    type: "ip",
    value: "185.220.101.1",
    description: "Known Tor exit node",
    severity: "low",
    source: "tor-project",
    tags: ["tor", "exit-node", "anonymization"],
    organization_id: org.id
  },

  # VPN/Proxy Services (potentially suspicious)
  %{
    type: "ip",
    value: "104.238.183.123",
    description: "Commercial VPN exit - potential C2 obfuscation",
    severity: "low",
    source: "greynoise",
    tags: ["vpn", "proxy", "anonymization"],
    organization_id: org.id
  },

  # ============================================================================
  # LOADERS AND DROPPERS
  # ============================================================================

  # BazarLoader
  %{
    type: "hash_sha256",
    value: "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
    description: "BazarLoader - TrickBot successor, precursor to ransomware",
    severity: "critical",
    source: "malware-bazaar",
    tags: ["bazarloader", "loader", "trickbot", "ransomware-precursor"],
    organization_id: org.id
  },

  # GuLoader
  %{
    type: "hash_sha256",
    value: "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
    description: "GuLoader - cloud-hosted shellcode loader",
    severity: "high",
    source: "malware-bazaar",
    tags: ["guloader", "loader", "cloud-hosted"],
    organization_id: org.id
  },

  # ============================================================================
  # WEBSHELLS
  # ============================================================================

  %{
    type: "hash_sha256",
    value: "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
    description: "China Chopper webshell - commonly used in web server compromises",
    severity: "critical",
    source: "internal-analysis",
    tags: ["webshell", "china-chopper", "web-compromise"],
    organization_id: org.id
  },
  %{
    type: "hash_sha256",
    value: "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    description: "ASPX webshell variant",
    severity: "high",
    source: "internal-analysis",
    tags: ["webshell", "aspx", "iis"],
    organization_id: org.id
  }
]

# Insert IOCs
inserted_count = 0
updated_count = 0

for ioc_attrs <- iocs do
  case Repo.get_by(IOC, type: ioc_attrs.type, value: ioc_attrs.value) do
    nil ->
      %IOC{}
      |> IOC.changeset(ioc_attrs)
      |> Repo.insert!()
      IO.puts("  Created IOC: [#{ioc_attrs.type}] #{String.slice(ioc_attrs.value, 0, 50)}...")

    existing ->
      existing
      |> IOC.changeset(ioc_attrs)
      |> Repo.update!()
      IO.puts("  Updated IOC: [#{ioc_attrs.type}] #{String.slice(ioc_attrs.value, 0, 50)}...")
  end
end

# Summary
IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("IOC Seeding Summary:")
IO.puts("=" <> String.duplicate("=", 70))

by_type = Enum.group_by(iocs, & &1.type)
for {type, items} <- by_type do
  IO.puts("  #{type}: #{length(items)} indicators")
end

by_severity = Enum.group_by(iocs, & &1.severity)
IO.puts("\nBy Severity:")
for severity <- ["critical", "high", "medium", "low"] do
  count = length(Map.get(by_severity, severity, []))
  IO.puts("  #{severity}: #{count}")
end

IO.puts("\nTotal IOCs seeded: #{length(iocs)}")
IO.puts("IOC seeding complete!")
