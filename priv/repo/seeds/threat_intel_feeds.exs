# Threat Intelligence Feeds Configuration
# Run with: mix run priv/repo/seeds/threat_intel_feeds.exs
#
# Configures integration with major threat intelligence sources
# used by enterprise EDR platforms.

IO.puts("Seeding threat intelligence feed configurations...")

# This seeds the ThreatIntel GenServer configuration
# In a production setup, these would be stored in the database

alias TamanduaServer.ThreatIntel

# Threat Intelligence Feed Definitions
# These represent integrations with major TI providers

threat_intel_feeds = [
  # ============================================================================
  # PUBLIC/FREE FEEDS
  # ============================================================================

  %{
    id: "alienvault-otx",
    name: "AlienVault OTX",
    description: """
    Open Threat Exchange (OTX) is the world's largest open threat intelligence
    community. Provides IOCs from security researchers worldwide including
    malware hashes, malicious IPs, domains, and URLs.
    """,
    provider: "AlienVault (AT&T Cybersecurity)",
    type: "community",
    url: "https://otx.alienvault.com/api/v1/pulses/subscribed",
    api_docs: "https://otx.alienvault.com/api",
    enabled: true,
    requires_api_key: true,
    api_key_env: "OTX_API_KEY",
    free_tier: true,
    rate_limit: "10000 requests/day",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "cve"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["community", "malware", "phishing", "botnet", "apt"],
    priority: 1
  },

  %{
    id: "abuse-ch-urlhaus",
    name: "URLhaus",
    description: """
    URLhaus is a project from abuse.ch with the goal of sharing malicious URLs
    that are being used for malware distribution. Updated every 5 minutes with
    new malware URLs.
    """,
    provider: "abuse.ch",
    type: "public",
    url: "https://urlhaus.abuse.ch/downloads/csv_recent/",
    api_docs: "https://urlhaus.abuse.ch/api/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 0.5,
    indicator_types: ["url", "domain"],
    data_format: "csv",
    confidence_scoring: false,
    tags: ["malware", "malware-distribution", "urls"],
    priority: 1
  },

  %{
    id: "abuse-ch-malwarebazaar",
    name: "MalwareBazaar",
    description: """
    MalwareBazaar is a project from abuse.ch sharing malware samples with the
    infosec community. Provides SHA256 hashes, file types, and malware family
    classifications.
    """,
    provider: "abuse.ch",
    type: "public",
    url: "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    api_docs: "https://bazaar.abuse.ch/api/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 1,
    indicator_types: ["hash_sha256", "hash_md5", "hash_sha1"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["malware", "samples", "hashes"],
    priority: 1
  },

  %{
    id: "abuse-ch-threatfox",
    name: "ThreatFox",
    description: """
    ThreatFox is a platform from abuse.ch for sharing IOCs associated with
    malware. Focuses on malware C2 infrastructure and provides context
    about malware families.
    """,
    provider: "abuse.ch",
    type: "public",
    url: "https://threatfox.abuse.ch/export/json/recent/",
    api_docs: "https://threatfox.abuse.ch/api/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_sha256"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["malware", "c2", "infrastructure"],
    priority: 1
  },

  %{
    id: "abuse-ch-feodotracker",
    name: "Feodo Tracker",
    description: """
    Feodo Tracker tracks botnet C2 infrastructure associated with banking
    trojans like Dridex, Emotet, TrickBot, and QakBot. Critical for
    financial sector threat detection.
    """,
    provider: "abuse.ch",
    type: "public",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    api_docs: "https://feodotracker.abuse.ch/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 1,
    indicator_types: ["ip"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["botnet", "banking-trojan", "emotet", "dridex", "trickbot"],
    priority: 1
  },

  %{
    id: "abuse-ch-sslbl",
    name: "SSL Blacklist",
    description: """
    SSLBL is a project from abuse.ch that detects malicious SSL connections
    by identifying and blacklisting SSL certificates used by botnet C2
    servers and malware.
    """,
    provider: "abuse.ch",
    type: "public",
    url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    api_docs: "https://sslbl.abuse.ch/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 6,
    indicator_types: ["ssl_fingerprint", "domain", "ip"],
    data_format: "csv",
    confidence_scoring: false,
    tags: ["ssl", "certificates", "botnet", "c2"],
    priority: 2
  },

  %{
    id: "cisa-kev",
    name: "CISA Known Exploited Vulnerabilities",
    description: """
    CISA's Known Exploited Vulnerabilities (KEV) Catalog contains CVEs that
    are being actively exploited in the wild. Essential for vulnerability
    prioritization and patch management.
    """,
    provider: "CISA (US Government)",
    type: "government",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    api_docs: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 24,
    indicator_types: ["cve"],
    data_format: "json",
    confidence_scoring: false,
    tags: ["vulnerability", "cve", "exploit", "government", "compliance"],
    priority: 1
  },

  %{
    id: "phishtank",
    name: "PhishTank",
    description: """
    PhishTank is a collaborative clearing house for data and information
    about phishing on the Internet. Community-verified phishing URLs
    with high accuracy.
    """,
    provider: "OpenDNS (Cisco)",
    type: "community",
    url: "https://data.phishtank.com/data/online-valid.json",
    api_docs: "https://www.phishtank.com/developer_info.php",
    enabled: true,
    requires_api_key: true,
    api_key_env: "PHISHTANK_API_KEY",
    free_tier: true,
    rate_limit: "100 requests/day",
    refresh_interval_hours: 1,
    indicator_types: ["url", "domain"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["phishing", "community", "verified"],
    priority: 1
  },

  %{
    id: "openphish",
    name: "OpenPhish",
    description: """
    OpenPhish uses proprietary Artificial Intelligence algorithms to
    automatically identify zero-day phishing sites and provide
    timely intelligence.
    """,
    provider: "OpenPhish",
    type: "commercial",
    url: "https://openphish.com/feed.txt",
    api_docs: "https://openphish.com/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 1,
    indicator_types: ["url"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["phishing", "ai-detected", "zero-day"],
    priority: 2
  },

  %{
    id: "emergingthreats",
    name: "Emerging Threats Open",
    description: """
    Emerging Threats provides a free rule set for network intrusion detection
    and IP reputation data. Widely used in IDS/IPS deployments worldwide.
    """,
    provider: "Proofpoint",
    type: "public",
    url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    api_docs: "https://doc.emergingthreats.net/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 6,
    indicator_types: ["ip"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["ids", "ips", "compromised", "network"],
    priority: 2
  },

  # ============================================================================
  # COMMERCIAL FEEDS (require subscription)
  # ============================================================================

  %{
    id: "virustotal",
    name: "VirusTotal",
    description: """
    VirusTotal aggregates data from 70+ antivirus scanners and URL/domain
    scanning services. Provides reputation data, behavioral analysis, and
    community-contributed information.
    """,
    provider: "Google (Chronicle)",
    type: "commercial",
    url: "https://www.virustotal.com/api/v3/",
    api_docs: "https://developers.virustotal.com/reference/overview",
    enabled: false,
    requires_api_key: true,
    api_key_env: "VIRUSTOTAL_API_KEY",
    free_tier: true,
    rate_limit: "4 requests/minute (free), 1000/day (premium)",
    refresh_interval_hours: 0,
    indicator_types: ["hash_md5", "hash_sha1", "hash_sha256", "ip", "domain", "url"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["multi-engine", "sandbox", "reputation", "behavioral"],
    priority: 1
  },

  %{
    id: "shodan",
    name: "Shodan",
    description: """
    Shodan is the world's first search engine for Internet-connected devices.
    Provides intelligence about exposed services, vulnerabilities, and
    honeypot detection for IP addresses.
    """,
    provider: "Shodan",
    type: "commercial",
    url: "https://api.shodan.io/",
    api_docs: "https://developer.shodan.io/api",
    enabled: false,
    requires_api_key: true,
    api_key_env: "SHODAN_API_KEY",
    free_tier: true,
    rate_limit: "1 request/second (free)",
    refresh_interval_hours: 0,
    indicator_types: ["ip"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["asset-discovery", "vulnerability", "exposure", "iot"],
    priority: 2
  },

  %{
    id: "greynoise",
    name: "GreyNoise",
    description: """
    GreyNoise collects and analyzes Internet-wide scan and attack data.
    Helps distinguish between targeted attacks and opportunistic scanning
    by identifying mass scanners and benign crawlers.
    """,
    provider: "GreyNoise Intelligence",
    type: "commercial",
    url: "https://api.greynoise.io/v3/",
    api_docs: "https://docs.greynoise.io/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "GREYNOISE_API_KEY",
    free_tier: true,
    rate_limit: "100 requests/day (community)",
    refresh_interval_hours: 0,
    indicator_types: ["ip"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["noise-reduction", "mass-scanner", "riot", "context"],
    priority: 2
  },

  %{
    id: "abuseipdb",
    name: "AbuseIPDB",
    description: """
    AbuseIPDB is a project dedicated to helping combat the spread of hackers,
    spammers, and abusive activity on the Internet. Community-reported
    malicious IPs with confidence scores.
    """,
    provider: "AbuseIPDB",
    type: "community",
    url: "https://api.abuseipdb.com/api/v2/blacklist",
    api_docs: "https://docs.abuseipdb.com/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "ABUSEIPDB_API_KEY",
    free_tier: true,
    rate_limit: "1000 requests/day (free)",
    refresh_interval_hours: 6,
    indicator_types: ["ip"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["community", "abuse-reports", "ip-reputation"],
    priority: 1
  },

  %{
    id: "pulsedive",
    name: "Pulsedive",
    description: """
    Pulsedive is a free threat intelligence platform that provides IOC
    enrichment, threat feed aggregation, and investigation tools. Aggregates
    data from multiple OSINT sources.
    """,
    provider: "Pulsedive",
    type: "community",
    url: "https://pulsedive.com/api/",
    api_docs: "https://pulsedive.com/api/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "PULSEDIVE_API_KEY",
    free_tier: true,
    rate_limit: "30 requests/minute (free)",
    refresh_interval_hours: 0,
    indicator_types: ["ip", "domain", "url", "hash_sha256"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["aggregator", "enrichment", "osint"],
    priority: 2
  },

  # ============================================================================
  # ENTERPRISE FEEDS (require enterprise subscription)
  # ============================================================================

  %{
    id: "crowdstrike-intel",
    name: "CrowdStrike Falcon Intelligence",
    description: """
    CrowdStrike's threat intelligence provides attribution-grade intelligence
    on adversaries, including detailed actor profiles, campaign tracking,
    and tactical IOCs.
    """,
    provider: "CrowdStrike",
    type: "enterprise",
    url: "https://api.crowdstrike.com/intel/",
    api_docs: "https://falcon.crowdstrike.com/documentation/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "CROWDSTRIKE_API_KEY",
    free_tier: false,
    rate_limit: "enterprise",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_md5", "hash_sha256", "email"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["enterprise", "attribution", "apt", "actor-tracking"],
    priority: 1
  },

  %{
    id: "mandiant-advantage",
    name: "Mandiant Advantage Threat Intelligence",
    description: """
    Mandiant (Google) provides intelligence from frontline incident response
    and security research. Includes detailed malware analysis, actor profiles,
    and strategic intelligence.
    """,
    provider: "Mandiant (Google)",
    type: "enterprise",
    url: "https://api.intelligence.mandiant.com/",
    api_docs: "https://www.mandiant.com/advantage/threat-intelligence",
    enabled: false,
    requires_api_key: true,
    api_key_env: "MANDIANT_API_KEY",
    free_tier: false,
    rate_limit: "enterprise",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_md5", "hash_sha256", "cve"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["enterprise", "apt", "incident-response", "malware-analysis"],
    priority: 1
  },

  %{
    id: "recorded-future",
    name: "Recorded Future Intelligence Cloud",
    description: """
    Recorded Future provides real-time threat intelligence by collecting and
    analyzing data from the open, deep, and dark web. Strong focus on
    predictive intelligence.
    """,
    provider: "Recorded Future",
    type: "enterprise",
    url: "https://api.recordedfuture.com/v2/",
    api_docs: "https://support.recordedfuture.com/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "RECORDED_FUTURE_API_KEY",
    free_tier: false,
    rate_limit: "enterprise",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_sha256", "cve"],
    data_format: "json",
    confidence_scoring: true,
    tags: ["enterprise", "dark-web", "predictive", "risk-scoring"],
    priority: 1
  },

  # ============================================================================
  # OPEN-SOURCE THREAT INTEL PLATFORMS (OSINT)
  # ============================================================================

  %{
    id: "misp-circl",
    name: "CIRCL MISP",
    description: """
    CIRCL operates a public MISP instance that shares threat intelligence
    from the Luxembourg CERT community. MISP is the de facto standard for
    threat intel sharing.
    """,
    provider: "CIRCL (Luxembourg CERT)",
    type: "community",
    url: "https://www.circl.lu/doc/misp/",
    api_docs: "https://www.misp-project.org/documentation/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "MISP_API_KEY",
    free_tier: true,
    rate_limit: "varies",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"],
    data_format: "misp",
    confidence_scoring: true,
    tags: ["misp", "community", "cert", "structured"],
    priority: 2
  },

  %{
    id: "opencti",
    name: "OpenCTI",
    description: """
    OpenCTI is an open-source platform allowing organizations to manage their
    cyber threat intelligence knowledge and observables. Integrates with
    MISP, STIX/TAXII, and other platforms.
    """,
    provider: "OpenCTI (Filigran)",
    type: "open-source",
    url: "https://demo.opencti.io/graphql",
    api_docs: "https://docs.opencti.io/latest/deployment/connectors/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "OPENCTI_API_KEY",
    free_tier: true,
    rate_limit: "varies",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_sha256"],
    data_format: "stix",
    confidence_scoring: true,
    tags: ["open-source", "platform", "stix", "taxii"],
    priority: 2
  },

  %{
    id: "taxii-server",
    name: "TAXII/STIX Feed",
    description: """
    Generic TAXII 2.1 server integration for consuming STIX-formatted threat
    intelligence. Compatible with any TAXII-compliant feed including
    government and ISAC feeds.
    """,
    provider: "Generic TAXII",
    type: "standard",
    url: "configurable",
    api_docs: "https://oasis-open.github.io/cti-documentation/",
    enabled: false,
    requires_api_key: true,
    api_key_env: "TAXII_API_KEY",
    free_tier: true,
    rate_limit: "varies",
    refresh_interval_hours: 1,
    indicator_types: ["ip", "domain", "url", "hash_sha256"],
    data_format: "stix",
    confidence_scoring: true,
    tags: ["taxii", "stix", "standard", "interoperable"],
    priority: 3
  },

  # ============================================================================
  # SPECIALIZED FEEDS
  # ============================================================================

  %{
    id: "spamhaus-drop",
    name: "Spamhaus DROP",
    description: """
    The Spamhaus Don't Route Or Peer (DROP) list is an advisory list of
    netblocks that are hijacked or leased by spammers or cyber criminals.
    Critical for network protection.
    """,
    provider: "Spamhaus",
    type: "public",
    url: "https://www.spamhaus.org/drop/drop.txt",
    api_docs: "https://www.spamhaus.org/drop/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 24,
    indicator_types: ["ip", "cidr"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["spam", "hijacked", "network", "blacklist"],
    priority: 1
  },

  %{
    id: "tor-exit-nodes",
    name: "Tor Exit Nodes",
    description: """
    List of known Tor exit node IP addresses. Useful for detecting anonymized
    traffic and applying appropriate security policies.
    """,
    provider: "Tor Project",
    type: "public",
    url: "https://check.torproject.org/torbulkexitlist",
    api_docs: "https://check.torproject.org/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 1,
    indicator_types: ["ip"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["tor", "anonymity", "exit-nodes"],
    priority: 2
  },

  %{
    id: "blocklist-de",
    name: "Blocklist.de",
    description: """
    Blocklist.de is a free and voluntary service to protect against attacks
    via fail2ban and other security tools. Community-maintained IP blocklists.
    """,
    provider: "Blocklist.de",
    type: "community",
    url: "https://lists.blocklist.de/lists/all.txt",
    api_docs: "https://www.blocklist.de/en/api.html",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 6,
    indicator_types: ["ip"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["fail2ban", "community", "attacks", "brute-force"],
    priority: 2
  },

  %{
    id: "cinsscore",
    name: "CI Army List",
    description: """
    The CI Army list is a subset of the CINS Active Threat Intelligence
    ruleset containing IPs with the worst reputation scores from commercial
    CINS scoring.
    """,
    provider: "Sentinel IPS",
    type: "public",
    url: "http://cinsscore.com/list/ci-badguys.txt",
    api_docs: "https://cinsscore.com/",
    enabled: true,
    requires_api_key: false,
    free_tier: true,
    rate_limit: "unlimited",
    refresh_interval_hours: 6,
    indicator_types: ["ip"],
    data_format: "txt",
    confidence_scoring: false,
    tags: ["reputation", "badguys", "commercial-grade"],
    priority: 2
  }
]

# Store feed configurations (in production, these would go to DB)
# For now, we'll output them as a reference

IO.puts("\nThreat Intelligence Feeds Summary:")
IO.puts("=" <> String.duplicate("=", 70))

enabled_feeds = Enum.filter(threat_intel_feeds, & &1.enabled)
disabled_feeds = Enum.filter(threat_intel_feeds, &(!&1.enabled))

IO.puts("\nEnabled Feeds (#{length(enabled_feeds)}):")
for feed <- enabled_feeds do
  key_status = if feed.requires_api_key, do: "[API KEY: #{feed.api_key_env}]", else: "[No Key Required]"
  IO.puts("  - #{feed.name} (#{feed.provider}) #{key_status}")
end

IO.puts("\nDisabled Feeds (#{length(disabled_feeds)}) - Require configuration:")
for feed <- disabled_feeds do
  key_status = if feed.requires_api_key, do: "[API KEY: #{feed.api_key_env}]", else: "[No Key Required]"
  IO.puts("  - #{feed.name} (#{feed.provider}) #{key_status}")
end

# Indicator types supported
all_indicator_types = threat_intel_feeds
|> Enum.flat_map(& &1.indicator_types)
|> Enum.uniq()
|> Enum.sort()

IO.puts("\nSupported Indicator Types: #{Enum.join(all_indicator_types, ", ")}")

IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("Threat intelligence feeds configuration complete!")
IO.puts("Total feeds configured: #{length(threat_intel_feeds)}")
IO.puts("Enabled feeds: #{length(enabled_feeds)}")
IO.puts("Feeds requiring API keys: #{Enum.count(threat_intel_feeds, & &1.requires_api_key)}")

# Export configuration for application use
# This would typically be loaded into the ThreatIntel GenServer

Application.put_env(:tamandua_server, :threat_intel_feeds, threat_intel_feeds)

IO.puts("\nFeed configuration stored in application environment.")
IO.puts("Access via: Application.get_env(:tamandua_server, :threat_intel_feeds)")
