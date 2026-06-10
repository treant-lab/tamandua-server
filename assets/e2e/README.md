# Tamandua EDR - E2E Tests

This directory contains end-to-end tests for the Tamandua EDR web interface using Playwright.

## Prerequisites

1. **Node.js** (v18+)
2. **PostgreSQL** (running and configured)
3. **Elixir/Phoenix** backend setup

## Setup

### 1. Install Dependencies

```bash
cd apps/tamandua_server/assets
npm install
npx playwright install chromium
```

### 2. Setup Database

```bash
cd apps/tamandua_server

# Create and migrate database
mix ecto.setup

# Seed test users (optional but recommended for auth tests)
mix run priv/repo/seeds/test_users.exs
```

### 3. Configure Environment

Create a `.env.test` file or export these variables:

```bash
# Database and server config
export DATABASE_URL=postgres://postgres:postgres@localhost/tamandua_test
export GUARDIAN_SECRET_KEY=test_secret_key_for_e2e_testing_only
export E2E_BASE_URL=http://localhost:4000

# Test user credentials (REQUIRED for auth tests)
# These must match users created in the database via seeds
export E2E_ADMIN_EMAIL=admin@example.com
export E2E_ADMIN_PASSWORD=YourSecurePassword123!
export E2E_ANALYST_EMAIL=analyst@example.com
export E2E_ANALYST_PASSWORD=AnalystPassword123!
export E2E_VIEWER_EMAIL=viewer@example.com
export E2E_VIEWER_PASSWORD=ViewerPassword123!
```

**Security Note**: Never commit real credentials. Use strong, unique passwords for test environments.

## Running Tests

### Option 1: Auto-start Server (Recommended)

```bash
# From apps/tamandua_server/assets
E2E_START_SERVER=1 npm run test:e2e
```

### Option 2: Manual Server Start

Terminal 1 - Start the server:
```bash
cd apps/tamandua_server
GUARDIAN_SECRET_KEY=test_secret_key mix phx.server
```

Terminal 2 - Run tests:
```bash
cd apps/tamandua_server/assets
npm run test:e2e
```

### Running Specific Tests

```bash
# Run a single test file
npx playwright test e2e/01-auth.spec.ts

# Run tests with UI mode
npx playwright test --ui

# Run tests in headed mode (see browser)
npx playwright test --headed

# Run tests with debug mode
npx playwright test --debug
```

## Test Files

| File | Description |
|------|-------------|
| `01-auth.spec.ts` | Authentication tests (login, logout, session) |
| `02-dashboard.spec.ts` | Dashboard page tests |
| `03-process-tree.spec.ts` | Process tree visualization tests |
| `04-navigation.spec.ts` | Navigation and routing tests |
| `05-api.spec.ts` | API endpoint tests |
| `06-accessibility.spec.ts` | Accessibility tests |
| `07-network.spec.ts` | Network page tests |
| `08-hunt.spec.ts` | Threat hunting page tests |
| `09-alerts.spec.ts` | Alerts page tests |
| `10-agents.spec.ts` | Agents page tests |
| `11-mitre.spec.ts` | MITRE ATT&CK page tests |
| `12-api-comprehensive.spec.ts` | Comprehensive API tests |

## Test Accounts

Test credentials are loaded from environment variables (no hardcoded credentials):

| User | Email Env Var | Password Env Var | Role |
|------|---------------|------------------|------|
| Admin | E2E_ADMIN_EMAIL | E2E_ADMIN_PASSWORD | admin |
| Analyst | E2E_ANALYST_EMAIL | E2E_ANALYST_PASSWORD | analyst |
| Viewer | E2E_VIEWER_EMAIL | E2E_VIEWER_PASSWORD | viewer |

**Note:** These accounts must be created in the database before running auth tests:

```bash
# Create test users with your chosen credentials
TAMANDUA_ADMIN_EMAIL=admin@example.com \
TAMANDUA_ADMIN_PASSWORD=YourSecurePassword123! \
mix run priv/repo/seeds/test_users.exs

# Then run tests with matching credentials
E2E_ADMIN_EMAIL=admin@example.com \
E2E_ADMIN_PASSWORD=YourSecurePassword123! \
npm run test:e2e
```

## Test Results

- HTML report: `test-results/` and `playwright-report/`
- Screenshots on failure: `test-results/`
- Videos on failure: `test-results/`
- Traces on retry: `test-results/`

View HTML report:
```bash
npx playwright show-report
```

## Configuration

Configuration is in `playwright.config.ts`:

- `baseURL`: Server URL (default: `http://localhost:4000`)
- `testDir`: Test directory (`./e2e`)
- `timeout`: Global timeout (60s)
- `workers`: Number of parallel workers (1 for consistency)
- `retries`: Retry count (2 in CI, 0 locally)

## CI/CD Integration

For CI environments, set `CI=true`:

```bash
CI=true npm run test:e2e
```

This enables:
- Strict mode (no `.only`)
- Automatic retries
- Screenshot/video on failure

## Troubleshooting

### Tests fail to connect
- Ensure Phoenix server is running on port 4000
- Check `E2E_BASE_URL` environment variable

### Database errors
- Ensure PostgreSQL is running
- Run `mix ecto.reset` to reset database
- Run seeds to create test users

### Authentication tests fail
- Ensure test users exist in database
- Run `mix run priv/repo/seeds/test_users.exs`

### Timeout errors
- Increase `timeout` in `playwright.config.ts`
- Check if server is responding slowly
- Run with `--debug` to see what's happening

## Writing New Tests

1. Create new file in `e2e/` with `.spec.ts` extension
2. Use helpers from `helpers/auth.ts` for authentication
3. Follow existing test patterns
4. Run with `--headed` to debug visually

Example:
```typescript
import { test, expect } from '@playwright/test';
import { login, waitForInertiaNavigation } from './helpers/auth';

test.describe('My Feature', () => {
  test.beforeEach(async ({ page }) => {
    await login(page, 'admin');
    await page.goto('/app/my-feature');
    await waitForInertiaNavigation(page);
  });

  test('feature works correctly', async ({ page }) => {
    // Test implementation
    await expect(page.locator('h1')).toContainText('My Feature');
  });
});
```
