# Threat Hunting Query Library - Complete Guide

## Overview

The Threat Hunting Query Library provides a comprehensive system for managing, sharing, and automating threat hunting queries in Tamandua EDR. It includes 70+ pre-built MITRE ATT&CK-mapped query templates and supports community sharing, scheduling, and performance analytics.

## Features

### 1. Saved Query Library

Store and organize your threat hunting queries with rich metadata:

- **Name and Description**: Clear identification and documentation
- **Categories**: MITRE ATT&CK tactics (Initial Access, Execution, etc.)
- **Tags**: Flexible tagging system (lateral-movement, credential-access, etc.)
- **MITRE Mapping**: Link queries to specific tactics (TA####) and techniques (T####)
- **Query Types**: Hunt (TQL), SQL, Sigma, YARA, NL (natural language)

### 2. Query Sharing

Three visibility levels for query sharing:

#### Private
- Only visible to the creator
- Personal hunting queries
- Draft/experimental queries

#### Organization
- Shared with all users in your organization
- Team collaboration
- Approved hunting playbooks

#### Public (Community Marketplace)
- Shared globally with the Tamandua community
- Download counts and ratings
- Attribution to authors

### 3. Community Features

#### Ratings & Reviews
- Upvote/downvote queries
- 1-5 star ratings
- Comments and discussions
- Community feedback

#### Statistics
- Use count tracking
- Download counts
- Performance metrics
- Trending queries

### 4. Query Parameterization

Create reusable queries with variables:

```
event_type:process_create AND timestamp > {timeframe} AND hostname:{target_host}
```

**Parameter Types:**
- `string`: Text values (hostnames, usernames)
- `number`: Numeric values (thresholds, counts)
- `date`: Timestamps and date ranges
- `boolean`: True/false flags

**Parameter Configuration:**
```elixir
%{
  "timeframe" => %{
    "type" => "string",
    "default" => "24h"
  },
  "target_host" => %{
    "type" => "string",
    "default" => "WORKSTATION-01"
  }
}
```

### 5. Query Scheduling

Automate query execution on a schedule:

#### Schedule Types
- **Hourly**: Every hour
- **Daily**: Once per day
- **Weekly**: Once per week
- **Monthly**: Once per month
- **Cron**: Custom cron expression

#### Alert Configuration
- Alert when results found
- Result threshold (alert if count > N)
- Multiple notification channels

#### Notification Channels
- **Email**: Send to multiple recipients
- **Slack**: Post to Slack channels
- **Webhook**: HTTP POST to custom URLs

### 6. Performance Analytics

Track and optimize query performance:

#### Metrics
- Average execution time
- Last execution time
- Total use count
- Last used timestamp

#### Optimization Suggestions
Automatically generated based on performance:
- Add database indexes
- Add time range filters
- Reduce selected fields
- Optimize query structure

### 7. Pre-Built Templates

70+ MITRE ATT&CK-mapped query templates included:

#### Initial Access (TA0001)
- Phishing Attachments Detection
- Drive-by Downloads
- Office Macro Execution
- Exploit Public-Facing Application

#### Execution (TA0002)
- PowerShell Encoded Commands
- PowerShell Download and Execute
- Windows Script Host Execution
- MSHTA LOLBin Abuse
- WMI Command Execution
- Regsvr32 Squiblydoo
- Rundll32 Suspicious Execution
- MSBuild Proxy Execution
- Command Shell with Chained Commands

#### Persistence (TA0003)
- Registry Run Keys Modification
- Scheduled Task Creation
- Service Installation
- WMI Event Subscription
- Startup Folder File Drops

#### Privilege Escalation (TA0004)
- UAC Bypass Attempts
- Token Manipulation
- Named Pipe Impersonation

#### Defense Evasion (TA0005)
- Process Hollowing Detection
- File Timestomping
- AMSI Bypass Attempts
- Disabling Windows Defender
- Event Log Clearing
- Masquerading Detection

#### Credential Access (TA0006)
- LSASS Memory Access
- Mimikatz Keywords Detection
- SAM Database Access
- NTDS.dit Extraction
- Credential Manager Access
- Keylogger Activity

#### Discovery (TA0007)
- System Information Discovery
- Network Configuration Discovery
- Active Directory Enumeration
- Process and Service Discovery
- Security Software Discovery

#### Lateral Movement (TA0008)
- PsExec Lateral Movement
- WMI Remote Command Execution
- RDP Connection Activity
- SMB Admin Share Access
- WinRM Remote Execution

#### Collection (TA0009)
- Archive Tools - Data Staging
- Screenshot Capture
- Email Collection

#### Command and Control (TA0011)
- Suspicious Port Communication
- DNS Tunneling Detection
- Long DNS Subdomain Queries
- Non-Standard HTTP Ports

#### Exfiltration (TA0010)
- Large Data Uploads
- Cloud Storage Service Access
- FTP Exfiltration
- Removable Media Data Copy

#### Impact (TA0040)
- Ransomware File Extensions
- Volume Shadow Copy Deletion
- Service Stop - Impact Phase
- Mass File Modifications

## Usage Examples

### Creating a Query

```elixir
# Via QueryLibrary module
alias TamanduaServer.Hunting.QueryLibrary

{:ok, query} = QueryLibrary.create_query(%{
  name: "Suspicious PowerShell Activity",
  description: "Detects PowerShell with encoded commands or download attempts",
  query: "event_type:process_create AND process.name:powershell.exe AND (process.cmdline:*-enc* OR process.cmdline:*downloadstring*)",
  query_type: "hunt",
  category: "Execution",
  tags: ["powershell", "execution", "encoded"],
  mitre_tactics: ["TA0002"],
  mitre_techniques: ["T1059.001"],
  visibility: "organization",
  created_by: user_id,
  organization_id: org_id
})
```

### Executing a Query

```elixir
# Execute saved query
{:ok, results} = QueryLibrary.execute_saved_query(query.id, user_id: user_id)

# Execute query text directly
{:ok, results} = SavedQueries.execute_query(
  "event_type:process_create AND process.name:mimikatz*",
  user_id: user_id
)
```

### Scheduling a Query

```elixir
alias TamanduaServer.Hunting.QueryScheduler

{:ok, schedule} = QueryScheduler.create_schedule(%{
  saved_query_id: query.id,
  user_id: user_id,
  organization_id: org_id,
  schedule_type: "daily",
  alert_on_results: true,
  result_threshold: 5,
  alert_channels: ["email", "slack"],
  notification_emails: ["security@company.com"],
  notification_slack_channels: ["#security-alerts"]
})

# Manually execute a scheduled query
{:ok, result_count} = QueryScheduler.execute_now(schedule.id)
```

### Adding Favorites

```elixir
# Add query to favorites (creates a personal copy)
{:ok, favorite_query} = QueryLibrary.add_favorite(query.id, user_id)

# List user's favorites
favorites = QueryLibrary.list_favorites(user_id)
```

### Rating Queries

```elixir
# Upvote a query
{:ok, _rating} = QueryLibrary.rate_query(query.id, user_id, vote: 1)

# Downvote a query
{:ok, _rating} = QueryLibrary.rate_query(query.id, user_id, vote: -1)

# Rate with stars (1-5)
{:ok, _rating} = QueryLibrary.rate_query(query.id, user_id, rating: 5)
```

### Commenting

```elixir
# Add a comment
{:ok, comment} = QueryLibrary.add_comment(
  query.id,
  user_id,
  "Great query! Works perfectly for detecting lateral movement."
)

# Reply to a comment
{:ok, reply} = QueryLibrary.add_comment(
  query.id,
  user_id,
  "Thanks! I've been refining it for weeks.",
  parent_id: comment.id
)

# List comments
comments = QueryLibrary.list_comments(query.id)
```

### Community Marketplace

```elixir
# Browse marketplace queries
popular = QueryLibrary.list_marketplace_queries(sort_by: :rating, limit: 20)
trending = QueryLibrary.list_marketplace_queries(sort_by: :trending)
recent = QueryLibrary.list_marketplace_queries(sort_by: :recent)

# Download/import a query
{:ok, imported_query} = QueryLibrary.download_query(
  marketplace_query_id,
  user_id,
  org_id
)
```

### Import/Export

```elixir
# Export single query to JSON
{:ok, json} = QueryLibrary.export_query(query.id)
File.write!("my_query.json", json)

# Import query from JSON
json = File.read!("my_query.json")
{:ok, query} = QueryLibrary.import_query(json, user_id, org_id)

# Export collection of queries
query_ids = [query1.id, query2.id, query3.id]
{:ok, json} = QueryLibrary.export_collection(query_ids, "My Hunt Collection")

# Import collection
{:ok, %{imported: count, total: total}} = QueryLibrary.import_collection(
  json,
  user_id,
  org_id
)
```

### Performance Analytics

```elixir
# Get performance stats
{:ok, stats} = QueryLibrary.get_query_performance(query.id)
# => %{
#   avg_execution_time_ms: 250,
#   last_execution_time_ms: 245,
#   use_count: 42,
#   last_used_at: ~U[2026-02-26 12:00:00Z]
# }

# Get optimization suggestions
{:ok, suggestions} = QueryLibrary.suggest_optimizations(query.id)
# => [
#   "Add a time range filter to reduce the data scanned",
#   "Select only the fields you need instead of using SELECT *"
# ]

# List slow queries
slow_queries = QueryLibrary.list_slow_queries(threshold_ms: 5000, limit: 10)
```

### Searching and Filtering

```elixir
# Search queries
results = QueryLibrary.list_queries(
  search: "powershell",
  category: "Execution",
  tags: ["lateral-movement", "credential-access"],
  mitre_tactic: "TA0002",
  user_id: user_id,
  limit: 50
)

# Filter by MITRE technique
queries = QueryLibrary.list_queries(mitre_technique: "T1059.001")

# List by category
by_category = QueryLibrary.templates_by_category()
# => %{
#   "Execution" => [query1, query2, ...],
#   "Persistence" => [query3, query4, ...],
#   ...
# }
```

## Web UI

### Query Library Page

Navigate to `/hunting/library` to access the query library interface.

**Features:**
- View tabs: My Queries, Templates, Organization, Marketplace, Favorites
- Search bar for text search
- Filters: Category, MITRE Tactic, Tags
- Sort options: Rating, Downloads, Recent, Trending
- Query cards with metadata, stats, and actions

### Query Editor Page

Navigate to `/hunting/query-editor` (new) or `/hunting/query-editor/:id` (edit).

**Features:**
- Query name and description
- Query type selector (Hunt/SQL/Sigma/YARA)
- Code editor with syntax support
- Parameter configuration
- MITRE mapping fields
- Tags input
- Execute button (run immediately)
- Schedule button (configure automated execution)
- Export button (download as JSON)
- Results viewer
- Performance sidebar (execution times, optimization suggestions)
- Schedules list (view/manage scheduled executions)

## Database Schema

### saved_queries
- Core query metadata and content
- Visibility and sharing settings
- Performance tracking
- Community features (ratings, downloads)
- MITRE mapping
- Version control

### query_schedules
- Schedule configuration (type, cron)
- Alert settings (threshold, channels)
- Notification recipients
- Execution tracking

### query_result_history
- Historical execution results
- Status tracking (success/error/timeout)
- Performance metrics
- Results summary

### query_ratings
- User votes (upvote/downvote)
- Star ratings (1-5)
- Comments/reviews

### query_comments
- Comments and replies
- Threaded discussions

### query_parameter_values
- Parameter values for scheduled queries
- Override defaults for automation

## Architecture

### Modules

#### QueryLibrary
Main context module for query management, search, filtering, and community features.

#### QueryScheduler
GenServer for automated query execution, scheduling, and notifications.

#### QueryTemplates
Pre-built MITRE-mapped query templates (70+).

#### SavedQuery
Ecto schema for saved queries.

#### QuerySchedule
Ecto schema for scheduled executions.

#### QueryRating, QueryComment, QueryResultHistory, QueryParameterValue
Supporting schemas for ratings, comments, history, and parameters.

### Process Flow

1. **Query Creation**: User creates query via UI or API
2. **Storage**: Query saved to database with metadata
3. **Sharing**: Query visibility controls access
4. **Scheduling**: Optional automated execution setup
5. **Execution**: QueryScheduler runs scheduled queries
6. **Alerting**: Notifications sent based on results
7. **History**: Results stored for trend analysis
8. **Analytics**: Performance tracked and optimizations suggested

## API Reference

See module documentation for complete API:

```bash
# Generate docs
mix docs

# View in browser
open doc/index.html
```

## Best Practices

### Query Design
1. **Be Specific**: Target specific event types and fields
2. **Use Time Windows**: Always include time range filters
3. **Test First**: Validate queries before scheduling
4. **Document Well**: Clear descriptions help team collaboration
5. **Tag Appropriately**: Tags improve searchability

### Performance
1. **Add Indexes**: Frequently queried fields should be indexed
2. **Limit Results**: Use LIMIT clauses for large datasets
3. **Monitor Execution**: Check avg_execution_time_ms regularly
4. **Optimize Slow Queries**: Act on optimization suggestions

### Scheduling
1. **Set Thresholds**: Alert only on meaningful result counts
2. **Choose Appropriate Frequency**: Don't over-schedule
3. **Test Notifications**: Verify alert channels work
4. **Monitor Failures**: Check schedule status regularly

### Community
1. **Share Quality Queries**: Only publish well-tested queries
2. **Provide Context**: Include detailed descriptions
3. **Map to MITRE**: Help others find relevant queries
4. **Engage with Comments**: Respond to feedback

## Troubleshooting

### Query Execution Fails
- Check query syntax
- Verify field names exist
- Ensure time range is valid
- Review error messages in query history

### Schedule Not Running
- Verify schedule is enabled
- Check next_execution_at timestamp
- Review last_execution_status
- Check QueryScheduler is running: `Process.whereis(TamanduaServer.Hunting.QueryScheduler)`

### Notifications Not Received
- Verify alert channels are configured
- Check notification email addresses
- Test Slack webhook URLs
- Review execution history for errors

### Slow Performance
- Check avg_execution_time_ms
- Run `QueryLibrary.suggest_optimizations(query.id)`
- Add time range filters
- Reduce selected fields
- Consider database indexes

## Migration and Seeding

### Run Migrations

```bash
cd apps/tamandua_server
mix ecto.migrate
```

### Seed Default Templates

```elixir
# In IEx console
alias TamanduaServer.Hunting.SavedQueries
{:ok, count} = SavedQueries.seed_default_templates()
# => {:ok, 70}
```

### Force Re-seed (Updates Existing)

```elixir
{:ok, count} = SavedQueries.reseed_templates!()
```

## Future Enhancements

- Query versioning and change tracking
- Advanced analytics dashboard
- Query recommendation engine
- AI-assisted query generation
- Cross-platform query translation
- Query performance benchmarking
- Collaborative editing
- Query collections/bundles
- Automated query tuning

## Support

For questions or issues:
- Check module documentation: `h TamanduaServer.Hunting.QueryLibrary`
- Review examples in this guide
- File issues on GitHub
- Contact support team
