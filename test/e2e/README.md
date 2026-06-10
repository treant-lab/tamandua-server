# E2E Tests for Tamandua EDR

This directory contains comprehensive end-to-end (E2E) tests for the Tamandua EDR platform using Wallaby and ExUnit.

## Overview

The E2E test suite covers all major user workflows and interactions:

- **Authentication** (`auth_test.exs`) - Login, MFA, SSO, password reset
- **Dashboard** (`dashboard_test.exs`) - Widgets, real-time updates, customization
- **Alerts** (`alerts_test.exs`) - Alert management, triage, correlation, timeline
- **Agents** (`agents_test.exs`) - Agent monitoring, configuration, isolation
- **Threat Hunting** (`threat_hunting_test.exs`) - Query builder, pivoting, campaigns
- **Settings** (`settings_test.exs`) - User/org settings, integrations, rule management
- **Compliance** (`compliance_test.exs`) - Frameworks, evidence, reports, assessments

## Setup

### Prerequisites

1. **ChromeDriver** (recommended) or **geckodriver** (Firefox)
   ```bash
   # macOS
   brew install chromedriver

   # Ubuntu/Debian
   sudo apt-get install chromium-chromedriver

   # Windows
   # Download from https://chromedriver.chromium.org/
   ```

2. **Install dependencies**
   ```bash
   cd apps/tamandua_server
   mix deps.get
   ```

3. **Setup test database**
   ```bash
   MIX_ENV=test mix ecto.create
   MIX_ENV=test mix ecto.migrate
   ```

## Running Tests

### Run all E2E tests
```bash
mix test test/e2e/
```

### Run specific test file
```bash
mix test test/e2e/auth_test.exs
```

### Run with visible browser (for debugging)
```bash
WALLABY_BROWSER=visible mix test test/e2e/auth_test.exs
```

### Run specific test
```bash
mix test test/e2e/auth_test.exs:42
```

### Run with more verbose output
```bash
mix test test/e2e/ --trace
```

## Test Structure

### Base Case (`test/support/e2e_case.ex`)

Provides common setup for all E2E tests:
- Wallaby session initialization
- Database sandbox setup
- Helper imports
- Common utilities

### Helpers (`test/support/e2e_helpers.ex`)

Provides reusable helper functions:
- `login_as/2` - Quick login with specific role
- `create_user/2` - Create test users
- `setup_organization/1` - Create org with agents
- `simulate_agent_event/3` - Trigger test events
- Navigation helpers
- Assertion helpers

### Factory (`test/support/factory.ex`)

Uses ExMachina for test data generation:
- `insert(:user)` - Create user
- `insert(:agent)` - Create agent
- `insert(:alert)` - Create alert
- `build(:event)` - Build event (no persist)

## Writing Tests

### Basic Test Structure

```elixir
defmodule TamanduaServer.E2E.MyFeatureTest do
  use TamanduaServer.E2ECase, async: false

  alias Wallaby.Query

  setup %{session: session} do
    user = insert(:user, role: "analyst")
    session = login_user(session, user)
    {:ok, session: session, user: user}
  end

  describe "my feature" do
    test "does something", %{session: session} do
      session
      |> visit("/my-page")
      |> assert_has(Query.css(".my-element"))
      |> click(Query.button("My Button"))
      |> assert_success("Operation successful")
    end
  end
end
```

### Common Patterns

#### Navigation
```elixir
session
|> visit("/alerts")
|> click(Query.link("View Details"))
|> assert_current_path("/alerts/123")
```

#### Form Interaction
```elixir
session
|> fill_in(Query.text_field("Email"), with: "user@example.com")
|> fill_in(Query.text_field("Password"), with: "password123")
|> click(Query.button("Submit"))
```

#### Assertions
```elixir
session
|> assert_has(Query.css(".success-message"))
|> assert_has(Query.text("Operation completed"))
|> refute_has(Query.css(".error"))
```

#### Waiting for Elements
```elixir
session
|> wait_for(Query.css(".loading-complete"), 5000)
|> wait_for_ajax()
|> wait_for_live_view()
```

#### Working with Tables
```elixir
session
|> sort_table_by("timestamp")
|> assert_table_row_count(20)
|> next_page()
```

#### Working with Modals
```elixir
session
|> open_modal("Create Alert")
|> fill_in(Query.text_field("Title"), with: "New Alert")
|> click(Query.button("Create"))
|> close_modal()
```

## Best Practices

### 1. Use Data Attributes for Selectors

Prefer `data-*` attributes over classes or IDs:
```elixir
# Good
Query.css("[data-alert-id='123']")
Query.css("[data-action='delete']")

# Avoid
Query.css("#alert-123")
Query.css(".btn-delete")
```

### 2. Use Descriptive Test Names

```elixir
# Good
test "user can assign alert to team member", %{session: session} do

# Avoid
test "assign", %{session: session} do
```

### 3. Set Up Test Data in Setup Block

```elixir
setup %{session: session} do
  org = insert(:organization)
  user = insert(:user, organization_id: org.id)
  agent = insert(:agent, organization_id: org.id)

  {:ok, session: session, org: org, user: user, agent: agent}
end
```

### 4. Wait for Asynchronous Operations

```elixir
session
|> click(Query.button("Save"))
|> wait_for_ajax()
|> assert_success("Saved successfully")
```

### 5. Use Helpers for Common Actions

```elixir
# Instead of repeating login steps
session = login_as(session, "admin")

# Instead of manual setup
%{organization: org, agents: agents} = setup_organization()
```

### 6. Test Both Success and Failure Paths

```elixir
test "shows error for invalid email", %{session: session} do
  session
  |> fill_in(Query.text_field("Email"), with: "invalid")
  |> click(Query.button("Submit"))
  |> assert_error("Invalid email format")
end
```

### 7. Clean Up After Tests

Tests use database sandbox, so changes are rolled back automatically.

### 8. Take Screenshots on Failure

Screenshots are automatically saved when tests fail:
```
tmp/screenshots/failure_<timestamp>.png
```

## Debugging

### View Browser During Test

```bash
WALLABY_BROWSER=visible mix test test/e2e/auth_test.exs
```

### Take Manual Screenshot

```elixir
session
|> take_screenshot("debug_step_1")
|> click(Query.button("Next"))
|> take_screenshot("debug_step_2")
```

### Print Current Page

```elixir
session
|> execute_js("return document.body.innerHTML")
|> IO.inspect()
```

### Use IEx for Interactive Debugging

```elixir
# Add to test
require IEx; IEx.pry()

# Then run with
iex -S mix test test/e2e/auth_test.exs
```

## Troubleshooting

### ChromeDriver Not Found

```bash
# Check if chromedriver is in PATH
which chromedriver

# Install if missing (macOS)
brew install chromedriver
```

### Tests Timeout

Increase wait time in config:
```elixir
# config/test.exs
config :wallaby,
  max_wait_time: 10_000  # 10 seconds
```

### Port Already in Use

```bash
# Kill process on port 4002
lsof -ti:4002 | xargs kill -9
```

### Database Connection Issues

```bash
# Reset test database
MIX_ENV=test mix ecto.drop
MIX_ENV=test mix ecto.create
MIX_ENV=test mix ecto.migrate
```

### Element Not Found

Add explicit waits:
```elixir
session
|> wait_for(Query.css(".my-element"), 5000)
|> click(Query.css(".my-element"))
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Set up Elixir
        uses: erlef/setup-beam@v1
        with:
          elixir-version: '1.15'
          otp-version: '26'

      - name: Install ChromeDriver
        run: |
          sudo apt-get update
          sudo apt-get install -y chromium-chromedriver

      - name: Install dependencies
        run: mix deps.get

      - name: Run E2E tests
        run: mix test test/e2e/
        env:
          MIX_ENV: test
          DATABASE_URL: postgres://postgres:postgres@localhost/tamandua_test
```

## Performance Considerations

- E2E tests are slower than unit tests (run in CI nightly if too slow)
- Use `async: false` to avoid database conflicts
- Consider running only critical E2E tests in PR checks
- Run full suite nightly or before releases

## Coverage

The E2E test suite covers:

- ✅ Authentication and authorization
- ✅ User management
- ✅ Dashboard and widgets
- ✅ Alert management and triage
- ✅ Agent monitoring and control
- ✅ Threat hunting queries
- ✅ Settings and configuration
- ✅ Compliance workflows
- ✅ Real-time updates (LiveView)
- ✅ Integration configurations
- ✅ Report generation

## Contributing

When adding new features:

1. Add E2E tests for critical user workflows
2. Use existing helpers when possible
3. Follow naming conventions
4. Test both happy path and error cases
5. Add screenshots for complex interactions
6. Update this README if adding new patterns

## Resources

- [Wallaby Documentation](https://hexdocs.pm/wallaby/)
- [ExUnit Documentation](https://hexdocs.pm/ex_unit/)
- [Phoenix Testing Guide](https://hexdocs.pm/phoenix/testing.html)
- [ExMachina Documentation](https://hexdocs.pm/ex_machina/)
