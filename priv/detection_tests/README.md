# Detection Rule Test Cases

This directory contains test cases for Tamandua EDR detection rules.

## Quick Reference

### Run All Tests
```bash
cd apps/tamandua_server
mix tamandua.test.rules
```

### Run Specific Tests
```bash
# By rule name
mix tamandua.test.rules --rule mimikatz

# By tag
mix tamandua.test.rules --tag credential_access

# Only Sigma rules
mix tamandua.test.rules --sigma

# Only YARA rules
mix tamandua.test.rules --yara
```

### Coverage
```bash
mix tamandua.test.rules --coverage
```

### Export Results
```bash
# JUnit XML (for CI/CD)
mix tamandua.test.rules --export junit

# HTML report
mix tamandua.test.rules --export html
```

## Test Case Structure

```yaml
test_case:
  name: "Descriptive Test Name"
  description: "What this test validates"
  rule: "category/rule_name.yml"
  rule_type: sigma  # or yara
  events:
    - type: process_create
      os_type: windows
      data:
        path: "C:\\malware.exe"
        cmdline: "malware.exe"
  expected: match  # or no_match
  expected_severity: critical  # optional
  expected_mitre: ["T1003.001"]  # optional
  tags: ["category", "tool"]  # optional
```

## Test Cases Included

### Credential Access (T1003)
- `01_mimikatz_command_line.yml` - Mimikatz sekurlsa commands
- `02_mimikatz_binary_name.yml` - Mimikatz binary detection
- `03_mimikatz_negative.yml` - Legitimate processes (negative test)
- `04_lsass_access.yml` - LSASS memory dumping
- `21_kerberoasting.yml` - Kerberos ticket abuse
- `22_dcsync.yml` - DCSync attack
- `23_sam_registry_access.yml` - SAM database dumping
- `24_ntds_dit_access.yml` - Active Directory database dumping

### Execution (T1059)
- `05_powershell_encoded.yml` - Encoded PowerShell commands
- `14_certutil_download.yml` - Certutil file download
- `15_bitsadmin_download.yml` - BITSAdmin abuse
- `17_mshta_execution.yml` - MSHTA proxy execution

### Persistence (T1547, T1053, T1543)
- `06_registry_run_key.yml` - Registry Run key modification
- `07_registry_run_key_legitimate.yml` - Legitimate Run key (negative)
- `11_scheduled_task_creation.yml` - Scheduled task persistence
- `12_service_creation.yml` - Malicious service creation

### Defense Evasion (T1562, T1070, T1218, T1036)
- `08_disable_defender.yml` - Windows Defender disabled
- `13_clear_event_logs.yml` - Event log clearing
- `16_rundll32_abuse.yml` - Rundll32 proxy execution
- `18_regsvr32_abuse.yml` - Regsvr32 squiblydoo
- `19_msbuild_abuse.yml` - MSBuild code execution
- `27_timestomping.yml` - File timestamp manipulation
- `28_process_hollowing.yml` - Process injection
- `29_masquerading.yml` - Process masquerading

### Lateral Movement (T1021)
- `09_psexec_lateral.yml` - PsExec usage
- `10_wmi_lateral.yml` - WMI-based lateral movement
- `25_winrm_lateral.yml` - WinRM remote execution
- `26_rdp_hijacking.yml` - RDP session hijacking

### Discovery (T1082, T1018)
- `30_system_info_discovery.yml` - System information enumeration
- `31_network_discovery.yml` - Network scanning

### Collection (T1113, T1560)
- `32_screen_capture.yml` - Screenshot capture
- `33_archive_collected_data.yml` - Data compression

### Command & Control (T1071)
- `20_dns_tunneling.yml` - DNS tunneling detection

### Impact (T1490, T1489)
- `34_ransomware_indicators.yml` - Shadow copy deletion
- `35_service_stop.yml` - Security service termination

## Adding New Test Cases

1. Create a new YAML file following the naming convention: `##_descriptive_name.yml`
2. Use the test case structure above
3. Include at least one positive and one negative test per rule
4. Tag appropriately for filtering
5. Run tests to verify:
   ```bash
   mix tamandua.test.rules --verbose
   ```

## Test Writing Guidelines

### Positive Tests
- Use realistic malicious patterns
- Include common attacker techniques
- Test actual malware command lines

### Negative Tests
- Ensure legitimate activities don't trigger false positives
- Test common administrative tasks
- Include filtered/whitelisted scenarios

### Edge Cases
- Boundary conditions
- Filter edge cases
- Encoding variations
- Case sensitivity

## Coverage Goals

- **Minimum**: 80% of rules have tests
- **Target**: Every rule has positive + negative tests
- **Ideal**: Every rule has positive + negative + edge cases

Current coverage:
```bash
mix tamandua.test.rules --coverage
```

## Integration with CI/CD

Tests run automatically on:
- Push to main/develop branches
- Pull requests affecting detection rules
- Manual workflow dispatch

See `.github/workflows/detection_tests.yml` for configuration.

## Documentation

This README is the public detection rule testing reference for this mirror. Extended
validation runbooks are maintained in private release materials.
