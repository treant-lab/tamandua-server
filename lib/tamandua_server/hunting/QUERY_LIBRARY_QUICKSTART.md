# Query Library - Quick Start Guide

## 5-Minute Getting Started

### 1. Access the Query Library

Navigate to: **Hunting → Query Library** or `/hunting/library`

### 2. Browse Pre-Built Templates

Click the **Templates** tab to see 70+ MITRE-mapped queries ready to use.

**Popular Templates:**
- PowerShell Encoded Command Execution
- LSASS Memory Access (Mimikatz)
- Lateral Movement via PsExec
- Ransomware File Extensions
- DNS Tunneling Detection

### 3. Run a Template Query

1. Click on any template query
2. Click **Run Query** button
3. View results instantly

### 4. Create Your First Query

```
1. Click "+ Create Query"
2. Fill in:
   - Name: "My PowerShell Hunt"
   - Description: "Detect suspicious PowerShell activity"
   - Query: event_type:process_create AND process.name:powershell.exe
   - Category: Execution
   - Tags: powershell, execution
3. Click "Create Query"
4. Click "Run Query" to test
```

### 5. Schedule Automated Execution

```
1. Open your query
2. Click "Schedule" button
3. Configure:
   - Schedule: Daily
   - Alert on results: Yes
   - Email: security@company.com
4. Click "Create Schedule"
```

Done! Your query now runs daily and alerts you of suspicious PowerShell activity.

## Common Use Cases

### Use Case 1: Hunt for Credential Dumping

**Template:** "LSASS Memory Access"

**When to use:** Daily monitoring for credential theft attempts

**Steps:**
1. Find template in Credential Access category
2. Click "Run" to test
3. Click "Schedule" → Set to Hourly
4. Enable email alerts
5. Set threshold: Alert if > 0 results

### Use Case 2: Detect Lateral Movement

**Template:** "PsExec Lateral Movement"

**When to use:** Real-time detection of lateral movement

**Steps:**
1. Find template in Lateral Movement category
2. Combine with other lateral movement queries:
   - WMI Remote Execution
   - RDP Connections
   - SMB Admin Share Access
3. Schedule all hourly with Slack alerts

### Use Case 3: Ransomware Detection

**Templates:**
- Ransomware File Extensions
- Volume Shadow Copy Deletion
- Mass File Modifications

**Steps:**
1. Import all 3 templates
2. Schedule each hourly
3. Set low threshold (> 0 for VSS deletion)
4. Send to #critical-alerts Slack channel

### Use Case 4: Share Query with Team

**Scenario:** You created a great detection query

**Steps:**
1. Edit your query
2. Change Visibility: Organization
3. Add MITRE mapping for discoverability
4. Add detailed description
5. Click "Update Query"

Now your entire team can use it!

### Use Case 5: Import Community Query

**Scenario:** Found useful query in marketplace

**Steps:**
1. Click "Community Marketplace" tab
2. Browse by rating or category
3. Click on interesting query
4. Click "Import"
5. Query copied to your library
6. Customize as needed

## Quick Reference Commands

### IEx Console Commands

```elixir
# Seed default templates
alias TamanduaServer.Hunting.SavedQueries
{:ok, 70} = SavedQueries.seed_default_templates()

# List all templates
alias TamanduaServer.Hunting.QueryLibrary
templates = QueryLibrary.list_queries(templates_only: true)

# Execute a query
{:ok, results} = SavedQueries.execute_query(
  "event_type:process_create AND process.name:mimikatz*",
  user_id: user_id
)

# Create a schedule
alias TamanduaServer.Hunting.QueryScheduler
{:ok, schedule} = QueryScheduler.create_schedule(%{
  saved_query_id: query.id,
  user_id: user_id,
  schedule_type: "daily",
  alert_on_results: true,
  notification_emails: ["admin@company.com"]
})
```

## Query Syntax Quick Reference

### Hunt Query Language (TQL)

```
# Basic field matching
event_type:process_create
process.name:powershell.exe

# Wildcards
process.path:*\\Windows\\System32\\*

# Logical operators
event_type:process_create AND process.name:cmd.exe
process.name:mimikatz* OR process.name:procdump*
process.name:svchost.exe AND process.parent_name:!services.exe

# Field existence
file.hash:*

# Numeric comparisons
network.bytes_sent:>1000000

# Multiple values
process.name:(powershell.exe OR cmd.exe OR wscript.exe)
```

### SQL Syntax

```sql
-- Process creation events
SELECT * FROM events
WHERE event_type = 'process_create'
AND timestamp > NOW() - INTERVAL '24 hours'
LIMIT 100

-- Aggregations
SELECT process.name, COUNT(*) as count
FROM events
WHERE event_type = 'process_create'
GROUP BY process.name
ORDER BY count DESC
LIMIT 10
```

## MITRE ATT&CK Quick Map

| Tactic | Example Techniques | Sample Query Template |
|--------|-------------------|----------------------|
| **TA0001** Initial Access | T1566 Phishing | "Phishing Attachments" |
| **TA0002** Execution | T1059 Command/Script | "PowerShell Encoded" |
| **TA0003** Persistence | T1547 Boot/Logon | "Registry Run Keys" |
| **TA0004** Privilege Escalation | T1548 UAC Bypass | "UAC Bypass Attempts" |
| **TA0005** Defense Evasion | T1070 Log Clearing | "Event Log Clearing" |
| **TA0006** Credential Access | T1003 Credential Dump | "LSASS Memory Access" |
| **TA0007** Discovery | T1082 System Info | "System Enumeration" |
| **TA0008** Lateral Movement | T1021 Remote Services | "PsExec Activity" |
| **TA0009** Collection | T1560 Archive Data | "Archive Creation" |
| **TA0010** Exfiltration | T1041 C2 Channel | "Large Data Uploads" |
| **TA0011** Command & Control | T1071 App Protocol | "DNS Tunneling" |
| **TA0040** Impact | T1486 Ransomware | "Ransomware Extensions" |

## Troubleshooting

### Query Returns No Results

**Possible causes:**
- Time range too narrow
- Field names incorrect
- Syntax error
- No matching events in database

**Solutions:**
1. Expand time range
2. Check field names: `event_type`, `process.name`, etc.
3. Test simpler query first
4. Check sample event structure

### Schedule Not Running

**Check:**
1. Schedule enabled? (toggle switch)
2. Next execution time correct?
3. QueryScheduler running? `Process.whereis(TamanduaServer.Hunting.QueryScheduler)`

### Slow Query Performance

**Quick fixes:**
1. Add time range filter
2. Reduce LIMIT
3. Be more specific with filters
4. Check optimization suggestions in query editor

## Best Practices Checklist

- [ ] Add description to every query
- [ ] Tag queries for easy searching
- [ ] Map to MITRE ATT&CK when applicable
- [ ] Test before scheduling
- [ ] Set reasonable alert thresholds
- [ ] Use time range filters
- [ ] Review scheduled query results weekly
- [ ] Share useful queries with team
- [ ] Rate community queries you use
- [ ] Document parameter usage

## Next Steps

1. **Explore Templates**: Review all 70+ pre-built templates
2. **Create Custom Queries**: Build queries for your environment
3. **Set Up Schedules**: Automate your top 10 hunts
4. **Join Community**: Share and download queries
5. **Advanced Features**: Try parameterized queries and collections

## Resources

- **Full Guide**: `QUERY_LIBRARY_GUIDE.md`
- **Module Docs**: `h TamanduaServer.Hunting.QueryLibrary`
- **Query Syntax**: `USAGE_EXAMPLES.md`
- **MITRE ATT&CK**: https://attack.mitre.org/

## Support

Questions? Check the full guide or contact the security team.

Happy Hunting! 🦊
