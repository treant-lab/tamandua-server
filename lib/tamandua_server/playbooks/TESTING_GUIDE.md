# Playbook Editor - Testing Guide

## Running Tests

### Run All Playbook Tests
```bash
# From apps/tamandua_server directory
mix test test/tamandua_server/playbooks/

# With coverage
mix test --cover test/tamandua_server/playbooks/

# Verbose output
mix test --trace test/tamandua_server/playbooks/
```

### Run Specific Test Files
```bash
# Validator tests only
mix test test/tamandua_server/playbooks/validator_test.exs

# Executor tests only
mix test test/tamandua_server/playbooks/executor_test.exs
```

### Run Specific Test Cases
```bash
# Run specific test
mix test test/tamandua_server/playbooks/validator_test.exs:10

# Run all tests matching pattern
mix test --only validation
```

## Manual Testing Checklist

### 1. Editor Loading
- [ ] Navigate to `/playbooks/editor`
- [ ] Monaco Editor loads successfully
- [ ] Default template appears in editor
- [ ] Syntax highlighting works
- [ ] Line numbers visible
- [ ] Minimap displays

### 2. Template Selection
- [ ] Load "Ransomware Auto-Response" template
- [ ] Load "Lateral Movement Response" template
- [ ] Load "Data Exfiltration Response" template
- [ ] Load "Credential Theft Response" template
- [ ] Editor content updates on template change
- [ ] No console errors

### 3. Validation
- [ ] Type valid YAML - green badge appears
- [ ] Type invalid YAML - red badge appears
- [ ] Validation messages display below editor
- [ ] Error messages are descriptive
- [ ] Warnings appear for action order issues
- [ ] Validation debounces (wait 500ms after typing)

### 4. Test Mode (Dry-Run)
- [ ] Click "Test (Dry-Run)" button
- [ ] Dry-run executes successfully
- [ ] Results appear in right panel
- [ ] All actions show as "simulated"
- [ ] Execution log displays timestamps
- [ ] Test with invalid playbook shows error
- [ ] Test with unmet triggers shows "skipped"

### 5. Save Functionality
- [ ] Save button disabled for invalid YAML
- [ ] Save button enabled for valid YAML
- [ ] Click save - success message appears
- [ ] Playbook appears in saved playbooks list
- [ ] Load saved playbook - content restored

### 6. Error Handling
- [ ] Test with malformed YAML syntax
- [ ] Test with missing required fields
- [ ] Test with invalid action types
- [ ] Test with invalid trigger conditions
- [ ] Test with invalid MITRE techniques
- [ ] All errors display helpful messages

## Test Scenarios

### Scenario 1: Create Ransomware Playbook

1. Load ransomware template
2. Modify trigger confidence to 0.95
3. Add additional action: `send_notification`
4. Validate - should be green
5. Test dry-run - should show 6 actions executed
6. Save playbook
7. Verify in database

**Expected Result**: Playbook saved successfully with all 6 actions

### Scenario 2: Invalid YAML Handling

1. Start with valid template
2. Remove `name` field
3. Observe validation error: "Missing required fields: name"
4. Add back `name` field
5. Remove all actions
6. Observe error: "actions cannot be empty"
7. Fix and validate

**Expected Result**: Clear error messages guide user to fix issues

### Scenario 3: Trigger Condition Testing

1. Create playbook with:
   ```yaml
   trigger:
     detection_type: "ransomware"
     confidence: 0.9
   ```
2. Test with context:
   ```
   detection_type: "malware"
   confidence: 0.95
   ```
3. Observe: Skipped due to detection_type mismatch
4. Change test context to `detection_type: "ransomware"`
5. Test again

**Expected Result**: Second test executes, first test skips

### Scenario 4: Action Order Warnings

1. Create playbook with actions:
   ```yaml
   actions:
     - action: "collect_forensics"
     - action: "isolate_host"
   ```
2. Validate
3. Observe warning: "Consider isolating host before collecting forensics"

**Expected Result**: Warning displayed but playbook still valid

### Scenario 5: Context Variable Resolution

1. Create playbook with:
   ```yaml
   actions:
     - action: "block_ip"
   ```
2. Test with context containing `remote_ip: "192.168.1.100"`
3. Check dry-run results
4. Verify IP is correctly used from context

**Expected Result**: Dry-run shows IP blocked: 192.168.1.100

## Integration Testing

### Test with Real Alert Context

```elixir
# In iex -S mix
alias TamanduaServer.Playbooks.Executor
alias TamanduaServer.Alerts

# Create test alert
{:ok, alert} = Alerts.create_alert(%{
  severity: "critical",
  title: "Ransomware Detected",
  agent_id: "test-agent-123",
  detection_metadata: %{"type" => "ransomware"},
  evidence: %{
    "file_path" => "C:\\malware.exe",
    "pid" => 1234,
    "process_name" => "malware.exe"
  },
  threat_score: 0.95
})

# Load and execute playbook
yaml = File.read!("lib/tamandua_server/playbooks/templates/ransomware.yaml")
{:ok, result} = Executor.execute(yaml, alert, dry_run: true)

IO.inspect(result, label: "Execution result")
```

### Test Playbook Engine Integration

```elixir
# Create playbook via editor
alias TamanduaServer.Response.Playbook

playbook_attrs = %{
  name: "Test Playbook",
  trigger_type: "alert",
  trigger_conditions: %{"detection_type" => "ransomware"},
  steps: [
    %{"action" => "isolate_host", "params" => %{}}
  ],
  enabled: true
}

{:ok, playbook} = Playbook.create_playbook(playbook_attrs)

# Trigger playbook with alert
Playbook.trigger_for_alert(alert)
```

## Performance Testing

### Validation Performance

```elixir
# Benchmark validation
yaml = File.read!("lib/tamandua_server/playbooks/templates/ransomware.yaml")

:timer.tc(fn ->
  for _ <- 1..100 do
    TamanduaServer.Playbooks.Validator.validate(yaml)
  end
end)
# Should complete in < 1 second for 100 validations
```

### Execution Performance

```elixir
# Benchmark dry-run execution
context = %{
  agent_id: "test-agent",
  detection_type: "ransomware",
  confidence: 0.95
}

:timer.tc(fn ->
  TamanduaServer.Playbooks.Executor.execute(yaml, context, dry_run: true)
end)
# Should complete in < 50ms
```

## Browser Testing

### Supported Browsers
- [ ] Chrome/Edge (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)

### Browser-Specific Tests
- [ ] Monaco Editor loads in all browsers
- [ ] YAML syntax highlighting works
- [ ] Validation feedback displays correctly
- [ ] LiveView events fire properly
- [ ] No JavaScript console errors

### Responsive Design
- [ ] Test on desktop (1920x1080)
- [ ] Test on laptop (1366x768)
- [ ] Test on tablet (768x1024)
- [ ] Editor remains usable at all sizes

## Security Testing

### Input Validation
- [ ] Test with extremely long YAML (>1MB)
- [ ] Test with deeply nested structures
- [ ] Test with special characters in strings
- [ ] Test with Unicode characters
- [ ] Test with YAML injection attempts

### XSS Prevention
- [ ] Test with `<script>alert('xss')</script>` in YAML
- [ ] Test with `javascript:` URLs
- [ ] Test with HTML entities
- [ ] Verify all output is properly escaped

### CSRF Protection
- [ ] Verify CSRF token present
- [ ] Test save without CSRF token (should fail)
- [ ] Test with invalid CSRF token (should fail)

## Load Testing

### Concurrent Users
```elixir
# Simulate 10 concurrent validations
tasks = for i <- 1..10 do
  Task.async(fn ->
    yaml = File.read!("lib/tamandua_server/playbooks/templates/ransomware.yaml")
    TamanduaServer.Playbooks.Validator.validate(yaml)
  end)
end

results = Task.await_many(tasks)
# All should succeed
```

### Large Playbooks
```yaml
# Test with 50 actions
name: "Large Playbook"
trigger: {}
actions:
  - action: "isolate_host"
  - action: "kill_process"
  # ... repeat 48 more times
```

## Regression Testing

### After Code Changes
1. [ ] Run full test suite
2. [ ] Manual test all templates
3. [ ] Test validation edge cases
4. [ ] Test dry-run execution
5. [ ] Test save/load functionality
6. [ ] Check for console errors
7. [ ] Verify performance hasn't degraded

## Common Test Failures

### Issue: Monaco Editor Not Loading
**Cause**: CDN blocked or network issue
**Fix**: Check browser console, verify CDN is accessible

### Issue: Validation Always Returns Invalid
**Cause**: YamlElixir dependency issue
**Fix**: Run `mix deps.get` and restart

### Issue: Dry-Run Fails
**Cause**: Missing required context fields
**Fix**: Ensure test context includes agent_id

### Issue: Save Fails
**Cause**: Database connection issue
**Fix**: Check Repo configuration, run migrations

## Test Data

### Valid Test Playbook
```yaml
name: "Test Playbook"
description: "For testing purposes"

trigger:
  detection_type: "malware"
  confidence: 0.8

actions:
  - action: "isolate_host"
  - action: "collect_forensics"
```

### Invalid Test Playbook (Missing Name)
```yaml
trigger:
  detection_type: "malware"
actions:
  - action: "isolate_host"
```

### Invalid Test Playbook (Invalid Action)
```yaml
name: "Bad Actions"
trigger: {}
actions:
  - action: "invalid_action_type"
```

### Complex Test Playbook
```yaml
name: "Complex Test"
trigger:
  detection_type: "ransomware"
  confidence: 0.9
  severity: "high"
  mitre_techniques:
    - "T1486"
actions:
  - action: "isolate_host"
  - action: "kill_process"
  - action: "quarantine_file"
  - action: "collect_forensics"
    collect_forensics:
      memory_dump: true
      process_list: true
  - action: "create_ticket"
    create_ticket:
      severity: "critical"
  - action: "send_notification"
    send_notification:
      channel: "slack"
      message: "Ransomware contained"
```

## Automated Test Commands

```bash
# Run all tests with coverage
mix test --cover

# Run only playbook tests
mix test test/tamandua_server/playbooks/

# Run tests in watch mode (requires mix_test_watch)
mix test.watch test/tamandua_server/playbooks/

# Run tests with specific tag
mix test --only validation

# Run tests excluding slow tests
mix test --exclude slow

# Generate test coverage report
mix coveralls.html
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Test Playbook Editor

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: erlef/setup-beam@v1
        with:
          elixir-version: '1.15'
          otp-version: '26'
      - run: mix deps.get
      - run: mix test test/tamandua_server/playbooks/
```

## Test Coverage Goals

- **Validator**: 95%+ line coverage
- **Executor**: 90%+ line coverage
- **LiveView**: 80%+ event handler coverage

Check coverage:
```bash
mix coveralls.detail
```

## Known Issues / Limitations

1. Monaco Editor requires JavaScript - no graceful fallback for JS-disabled browsers
2. Validation is client-side debounced - may feel slow on very slow connections
3. Large playbooks (>100 actions) may impact editor performance
4. Template files must exist on disk or fallbacks are used

## Next Steps After Testing

1. Deploy to staging environment
2. Conduct user acceptance testing with security analysts
3. Gather feedback on UX and validation messages
4. Monitor production metrics (validation times, error rates)
5. Iterate based on real-world usage
