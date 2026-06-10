# OSINT Threat Intelligence Feed Integration

Comprehensive OSINT (Open Source Intelligence) feed integration for Tamandua EDR with automated IOC imports, enrichment, and alert correlation.

## Overview

The OSINT Feed Manager orchestrates multiple threat intelligence feeds to provide real-time IOC (Indicator of Compromise) data for detection and enrichment.

### Supported Feeds

| Feed | Type | API Key Required | IOC Types | Update Frequency |
|------|------|------------------|-----------|------------------|
| **AlienVault OTX** | Premium | Yes (Free tier available) | IP, Domain, URL, Hash, Email | 6 hours |
| **Abuse.ch** | Free | No | IP, Domain, URL, Hash | 4 hours |
| **PhishTank** | Free | No | URL | 2 hours |
| **Emerging Threats** | Free | No | IP | 6 hours |
| **GreyNoise** | Premium | Yes (Community tier free) | IP | 12 hours |
| **Shodan** | Premium | Yes | IP (enrichment only) | On-demand |

## Architecture

```
┌─────────────────────────────────────┐
│   OSINTFeedManager (Orchestrator)   │
└─────────────────┬───────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼────┐  ┌────▼────┐  ┌────▼────┐
│ OTX    │  │Abuse.ch │  │PhishTank│
│AlienVlt│  │         │  │         │
└───┬────┘  └────┬────┘  └────┬────┘
    │            │            │
    └────────────┼────────────┘
                 │
         ┌───────▼────────┐
         │   Aggregator   │
         │  (Dedup + Score)│
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │  IOC Database  │
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │Detection Engine│
         └────────────────┘
```

## Quick Start

### 1. Configure API Keys (Optional)

API keys are optional for free feeds but required for premium features:

```bash
# In your environment (.env or system environment)
export OTX_API_KEY="your-alienvault-otx-key"
export GREYNOISE_API_KEY="your-greynoise-key"
export SHODAN_API_KEY="your-shodan-key"
```

Or configure via Elixir:

```elixir
# config/runtime.exs
config :tamandua_server, :threat_intel,
  alienvault_api_key: System.get_env("OTX_API_KEY"),
  greynoise_api_key: System.get_env("GREYNOISE_API_KEY"),
  shodan_api_key: System.get_env("SHODAN_API_KEY")
```

### 2. Enable Feeds

```elixir
# Enable specific feeds
TamanduaServer.ThreatIntel.OSINTFeedManager.enable_feed(:abuse_ch)
TamanduaServer.ThreatIntel.OSINTFeedManager.enable_feed(:emerging_threats)
TamanduaServer.ThreatIntel.OSINTFeedManager.enable_feed(:phishtank)

# Enable premium feeds (requires API key)
TamanduaServer.ThreatIntel.OSINTFeedManager.configure_api_key(:alienvault_otx, "your-key")
TamanduaServer.ThreatIntel.OSINTFeedManager.enable_feed(:alienvault_otx)
```

### 3. Manual Sync (Optional)

Feeds sync automatically, but you can trigger manual updates:

```elixir
# Sync specific feed
TamanduaServer.ThreatIntel.OSINTFeedManager.sync_feed(:abuse_ch)

# Sync all enabled feeds
TamanduaServer.ThreatIntel.OSINTFeedManager.sync_all()
```

## Feed Details

### AlienVault OTX

**Website:** https://otx.alienvault.com/

**Free Tier:** ✅ Yes (requires registration)
- API calls: 10,000/hour
- Pulse subscriptions: Unlimited
- Indicator lookups: Full access

**Features:**
- Community-driven threat intelligence
- Pulse subscriptions (threat reports)
- Indicator lookups with context
- File, URL, IP, domain analysis

**Configuration:**
```elixir
# Get API key from: https://otx.alienvault.com/api
OSINTFeedManager.configure_api_key(:alienvault_otx, "YOUR_OTX_KEY")
OSINTFeedManager.enable_feed(:alienvault_otx)
```

### Abuse.ch

**Website:** https://abuse.ch/

**Free Tier:** ✅ Yes (no API key required)
- Full access to all feeds
- No rate limits
- Free for commercial use

**Feeds:**
- **MalwareBazaar:** Malware samples and hashes
- **URLhaus:** Malicious URLs
- **ThreatFox:** IOC sharing platform
- **Feodo Tracker:** Banking trojan C2s
- **SSL Blacklist:** Malicious SSL certificates

**Features:**
- High-quality, vetted IOCs
- Malware family attribution
- File type and signature information
- No authentication required

**Configuration:**
```elixir
# Enabled by default, no API key needed
OSINTFeedManager.enable_feed(:abuse_ch)
```

### PhishTank

**Website:** https://www.phishtank.com/

**Free Tier:** ✅ Yes (API key optional for higher limits)
- Without API key: ~1000 URLs/hour
- With API key: Higher rate limits

**Features:**
- Community-verified phishing URLs
- Real-time phishing detection
- Target identification (PayPal, Amazon, etc.)
- Submission timestamps

**Configuration:**
```elixir
# Works without API key
OSINTFeedManager.enable_feed(:phishtank)

# Or configure API key for higher limits
OSINTFeedManager.configure_api_key(:phishtank, "YOUR_KEY")
```

### Emerging Threats

**Website:** https://rules.emergingthreats.net/

**Free Tier:** ✅ Yes
- Free IP blocklists
- Daily updates
- No registration required

**Feeds:**
- Compromised IPs
- Botnet C2 infrastructure
- DShield blocklist
- Tor exit nodes
- Known malicious actors

**Configuration:**
```elixir
# Free, no API key required
OSINTFeedManager.enable_feed(:emerging_threats)
```

### GreyNoise

**Website:** https://www.greynoise.io/

**Free Tier:** ✅ Community API (50 lookups/day)
- Basic IP classification
- Noise vs. malicious determination
- RIOT identification (legitimate services)

**Paid Tiers:**
- **Researcher:** $50/month, 5000 lookups/day
- **Enterprise:** Custom pricing, unlimited

**Features:**
- Internet background noise filtering
- Malicious actor identification
- RIOT dataset (known good IPs)
- Tag-based classification
- GNQL queries (paid tier)

**Configuration:**
```elixir
# Get API key from: https://www.greynoise.io/
OSINTFeedManager.configure_api_key(:greynoise, "YOUR_GN_KEY")
OSINTFeedManager.enable_feed(:greynoise)
```

**Use Cases:**
- Reduce false positives by filtering scanning noise
- Identify legitimate services (CDNs, cloud providers)
- Focus on true threats vs. benign scanners

### Shodan

**Website:** https://www.shodan.io/

**Free Tier:** ❌ No (API key required)
- **Small:** $49/month, 10,000 results
- **Developer:** $59/month, 100,000 results
- **Enterprise:** Custom pricing

**Features:**
- IP enrichment (ports, services, vulnerabilities)
- Infrastructure intelligence
- Banner grabbing
- Geolocation data

**Configuration:**
```elixir
# Get API key from: https://account.shodan.io/
OSINTFeedManager.configure_api_key(:shodan, "YOUR_SHODAN_KEY")

# Shodan is used for enrichment, not as a feed
# It's automatically used when enriching IP IOCs
```

**Note:** Shodan is used for on-demand enrichment rather than as a scheduled feed.

## Custom Feeds

Add your own threat intelligence feeds:

```elixir
OSINTFeedManager.add_custom_feed(
  "My Custom Feed",                    # Name
  "https://example.com/iocs.txt",      # URL
  enabled: true,                        # Auto-enable
  ioc_type: :ip,                        # IP, domain, url, hash_*, email, or :auto
  format: :plain_text,                  # plain_text, json, csv
  severity: "high",                     # low, medium, high, critical
  confidence: 0.85,                     # 0.0 to 1.0
  sync_interval: :timer.hours(6),       # Update frequency
  headers: [{"Authorization", "Bearer token"}]  # Custom headers
)
```

**Supported Formats:**

**Plain Text:**
```
# Comments start with #
1.2.3.4
5.6.7.8
evil.com
```

**JSON:**
```json
[
  {
    "value": "1.2.3.4",
    "severity": "critical",
    "confidence": 0.9,
    "tags": ["c2", "malware"]
  }
]
```

**CSV:**
```csv
type,value,severity,confidence
ip,1.2.3.4,high,0.8
domain,evil.com,critical,0.95
```

## Management API

### Enable/Disable Feeds

```elixir
# Enable
OSINTFeedManager.enable_feed(:abuse_ch)

# Disable
OSINTFeedManager.disable_feed(:phishtank)
```

### Get Status

```elixir
# Overall status
status = OSINTFeedManager.get_status()
# => %{
#   total_feeds: 6,
#   enabled_feeds: 4,
#   disabled_feeds: 2,
#   total_iocs: 125000,
#   iocs_by_type: %{"ip" => 50000, "domain" => 25000, ...},
#   iocs_by_source: %{"abuse_ch" => 30000, ...}
# }

# Feed health
health = OSINTFeedManager.get_feed_health()
# => %{
#   abuse_ch: %{
#     status: :healthy,
#     health_score: 95,
#     last_check: ~U[2024-01-20 15:30:00Z],
#     issues: []
#   },
#   ...
# }

# Feed statistics
stats = OSINTFeedManager.get_statistics()
# => %{
#   abuse_ch: %{
#     total_syncs: 120,
#     successful_syncs: 118,
#     failed_syncs: 2,
#     total_iocs_imported: 35000,
#     last_import_count: 150,
#     average_sync_time_ms: 3500
#   },
#   ...
# }
```

### List Feeds

```elixir
feeds = OSINTFeedManager.list_feeds()
# => [
#   %{
#     id: :abuse_ch,
#     name: "Abuse.ch",
#     enabled: true,
#     requires_api_key: false,
#     sync_interval_hours: 4,
#     priority: :high,
#     ioc_types: [:ip, :domain, :url, :hash_sha256],
#     last_sync: ~U[2024-01-20 14:00:00Z],
#     health_status: :healthy,
#     total_iocs_imported: 35000
#   },
#   ...
# ]
```

## IOC Deduplication & Scoring

The Aggregator automatically:

1. **Deduplicates** IOCs from multiple sources
2. **Scores confidence** based on:
   - Source reputation
   - Number of sources reporting the IOC
   - Age of the indicator
   - Historical accuracy

3. **Prioritizes** based on:
   - Severity level
   - Confidence score
   - Recency

**Example:**

If an IP appears in both Abuse.ch and AlienVault OTX:
```elixir
IOCs.lookup("ip", "1.2.3.4")
# => {:ok, %IOC{
#   value: "1.2.3.4",
#   sources: ["abuse_ch", "alienvault_otx"],
#   confidence: 0.92,  # Boosted from multi-source
#   severity: "critical",
#   tags: ["c2", "emotet", "malware"]
# }}
```

## IOC Expiration

IOCs automatically expire based on:
- **Feed-specific TTL:** Each feed defines how long its IOCs are valid
- **Age-based decay:** Older IOCs have reduced confidence
- **Manual expiration:** Set `expires_at` field

**Automatic Cleanup:**

The feed manager runs hourly expiration checks:

```elixir
# Expired IOCs are automatically removed
# Check interval: 1 hour
# Logs: "[OSINTFeedManager] Expired 150 IOCs"
```

**Manual Expiration:**

```elixir
# Set expiration when creating IOC
IOCs.add(%{
  type: "ip",
  value: "1.2.3.4",
  source: "manual",
  expires_at: DateTime.add(DateTime.utc_now(), 30, :day)
})
```

## Alert Correlation

IOCs are automatically used by the Detection Engine:

```elixir
# In your detection logic
case IOCs.lookup("ip", dst_ip) do
  {:ok, ioc} ->
    # IOC match found - generate alert
    create_alert(
      type: :ioc_match,
      severity: ioc.severity,
      confidence: ioc.confidence,
      description: "Connection to known malicious IP: #{ioc.value}",
      ioc: ioc,
      sources: ioc.sources,
      tags: ioc.tags,
      metadata: %{
        malware_family: ioc.malware_family,
        threat_actor: ioc.threat_actor,
        campaign: ioc.campaign
      }
    )

  {:error, :not_found} ->
    # Not a known IOC
    :ok
end
```

## Feed Health Monitoring

### Health Scores (0-100)

- **100:** Perfect health
- **75-99:** Healthy
- **50-74:** Degraded
- **25-49:** Unhealthy
- **0-24:** Critical

### Health Status

- **pending:** Waiting for first sync
- **healthy:** Operating normally
- **degraded:** Some issues but functional
- **unhealthy:** Frequent failures
- **stale:** No updates for extended period

### Monitoring

```elixir
# Check feed health
health = OSINTFeedManager.get_feed_health()

Enum.each(health, fn {feed_name, feed_health} ->
  if feed_health.health_score < 50 do
    # Alert operations team
    Logger.error("[OSINT] Feed #{feed_name} is unhealthy: score=#{feed_health.health_score}")

    # Check issues
    Enum.each(feed_health.issues, fn {issue_type, description} ->
      Logger.error("  - #{issue_type}: #{description}")
    end)
  end
end)
```

## Troubleshooting

### Feed Not Syncing

**Check if enabled:**
```elixir
feeds = OSINTFeedManager.list_feeds()
feed = Enum.find(feeds, &(&1.id == :abuse_ch))
feed.enabled  # Should be true
```

**Check health:**
```elixir
health = OSINTFeedManager.get_feed_health()
health[:abuse_ch]
# => %{status: :unhealthy, issues: [{:sync_error, "HTTP 429"}]}
```

**Force sync:**
```elixir
OSINTFeedManager.sync_feed(:abuse_ch)
```

### API Key Issues

**GreyNoise "Invalid API Key":**
```bash
# Verify API key is set
echo $GREYNOISE_API_KEY

# Test directly
curl -H "key: $GREYNOISE_API_KEY" https://api.greynoise.io/v2/noise/context/8.8.8.8
```

**AlienVault OTX "Forbidden":**
```elixir
# Reconfigure API key
OSINTFeedManager.configure_api_key(:alienvault_otx, "NEW_KEY")

# Verify
AlienVault.api_info()
```

### Rate Limiting

**GreyNoise "Rate Limited":**

Community tier is limited to 50 requests/day. Upgrade to Researcher tier or reduce sync frequency:

```elixir
# Custom feeds can override sync interval
# But built-in feeds use default intervals
```

**PhishTank Timeouts:**

PhishTank can be slow. Increase timeout or reduce frequency:

```elixir
# Feeds automatically retry with exponential backoff
# Check sync history for timing issues
```

### No IOCs Imported

**Check statistics:**
```elixir
stats = OSINTFeedManager.get_statistics()
stats[:abuse_ch]
# => %{total_syncs: 5, successful_syncs: 5, total_iocs_imported: 0}
```

**Possible causes:**
1. Feed returned no data (normal for some feeds)
2. All IOCs were duplicates (already in database)
3. Parsing error (check logs)

**Check logs:**
```bash
grep "OSINTFeedManager" logs/dev.log | grep ERROR
```

### Memory Usage

**IOC Count:**
```elixir
status = OSINTFeedManager.get_status()
status.total_iocs  # If > 1 million, consider cleanup
```

**Cleanup expired IOCs:**
```sql
-- Run manually if needed
DELETE FROM iocs WHERE expires_at < NOW();
```

**Disable unused feeds:**
```elixir
OSINTFeedManager.disable_feed(:greynoise)
OSINTFeedManager.disable_feed(:phishtank)
```

## Performance

### Caching

All feeds use caching to reduce API calls:

- **AlienVault OTX:** 6-hour cache
- **GreyNoise:** 24-hour cache
- **Shodan:** 12-hour cache

### Bloom Filters

The Aggregator uses bloom filters for fast negative lookups:

- **Size:** ~144 MB for 10M IOCs
- **False Positive Rate:** 0.1%
- **Lookup Time:** O(1)

### Database Indexes

Optimized indexes for fast IOC lookups:

```sql
-- Existing indexes
CREATE INDEX iocs_type_value_idx ON iocs (type, value);
CREATE INDEX iocs_value_idx ON iocs (value);
CREATE INDEX iocs_source_idx ON iocs (source);
```

### Sync Performance

Average sync times:

- **Abuse.ch:** 3-5 seconds (10,000 IOCs)
- **Emerging Threats:** 2-3 seconds (5,000 IOCs)
- **PhishTank:** 10-15 seconds (15,000 IOCs)
- **AlienVault OTX:** 30-45 seconds (50,000 IOCs)

## Best Practices

1. **Start with free feeds:**
   - Abuse.ch
   - Emerging Threats
   - PhishTank

2. **Add premium feeds as needed:**
   - AlienVault OTX for comprehensive coverage
   - GreyNoise for noise reduction
   - Shodan for infrastructure intelligence

3. **Monitor health regularly:**
   - Set up alerts for unhealthy feeds
   - Review sync failures
   - Track IOC import rates

4. **Tune confidence thresholds:**
   - Adjust based on false positive rates
   - Consider source reputation
   - Use multi-source correlation

5. **Regular cleanup:**
   - Enable automatic expiration
   - Remove stale IOCs
   - Prune old sync history

## API Reference

See module documentation for complete API:

- `TamanduaServer.ThreatIntel.OSINTFeedManager`
- `TamanduaServer.ThreatIntel.Feeds.GreyNoise`
- `TamanduaServer.Detection.ThreatIntel.AlienVault`
- `TamanduaServer.Detection.ThreatIntel.AbuseCh`
- `TamanduaServer.ThreatIntel.Feeds.PhishTank`
- `TamanduaServer.ThreatIntel.Feeds.EmergingThreats`
- `TamanduaServer.ThreatIntel.Aggregator`

## License

Part of Tamandua EDR. See main repository LICENSE file.
