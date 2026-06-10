import { test as base, expect, Page } from '@playwright/test';

/**
 * Test credentials for E2E testing
 * These should match seeded test users in the database
 * (Consistent with helpers/auth.ts)
 *
 * Credentials are loaded from environment variables:
 *   - E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD
 *   - E2E_ANALYST_EMAIL / E2E_ANALYST_PASSWORD
 *   - E2E_VIEWER_EMAIL / E2E_VIEWER_PASSWORD
 *
 * If not set, tests will fail with a clear error message.
 */
function getEnvOrThrow(key: string, description: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${key}\n` +
      `Please set ${key} for ${description}.\n` +
      `Example: ${key}=your-value npm run test:e2e`
    );
  }
  return value;
}

export const TEST_USERS = {
  admin: {
    get email() { return getEnvOrThrow('E2E_ADMIN_EMAIL', 'admin user email'); },
    get password() { return getEnvOrThrow('E2E_ADMIN_PASSWORD', 'admin user password'); },
    description: 'System Administrator',
    role: 'admin',
  },
  analyst: {
    get email() { return getEnvOrThrow('E2E_ANALYST_EMAIL', 'analyst user email'); },
    get password() { return getEnvOrThrow('E2E_ANALYST_PASSWORD', 'analyst user password'); },
    description: 'Security Analyst',
    role: 'analyst',
  },
  viewer: {
    get email() { return getEnvOrThrow('E2E_VIEWER_EMAIL', 'viewer user email'); },
    get password() { return getEnvOrThrow('E2E_VIEWER_PASSWORD', 'viewer user password'); },
    description: 'Read-only Viewer',
    role: 'viewer',
  },
} as const;

/**
 * Custom test fixture with authentication helpers
 */
export interface TestFixtures {
  /** Login as a specific user */
  login: (email: string, password: string) => Promise<void>;
  /** Login as admin user */
  loginAsAdmin: () => Promise<void>;
  /** Login as analyst user */
  loginAsAnalyst: () => Promise<void>;
  /** Logout current user */
  logout: () => Promise<void>;
  /** Check if currently logged in */
  isLoggedIn: () => Promise<boolean>;
}

/**
 * Extended test with custom fixtures
 */
export const test = base.extend<TestFixtures>({
  login: async ({ page }, use) => {
    const loginFn = async (email: string, password: string) => {
      await page.goto('/login');
      await page.waitForLoadState('networkidle');

      // Fill login form
      await page.getByLabel(/email/i).fill(email);
      await page.getByLabel(/password/i).fill(password);

      // Submit form
      await page.getByRole('button', { name: /sign in|log in|login/i }).click();

      // Wait for redirect after successful login
      await page.waitForURL((url) => !url.pathname.includes('/login'), {
        timeout: 10000,
      });
    };
    await use(loginFn);
  },

  loginAsAdmin: async ({ login }, use) => {
    const loginAsAdminFn = async () => {
      await login(TEST_USERS.admin.email, TEST_USERS.admin.password);
    };
    await use(loginAsAdminFn);
  },

  loginAsAnalyst: async ({ login }, use) => {
    const loginAsAnalystFn = async () => {
      await login(TEST_USERS.analyst.email, TEST_USERS.analyst.password);
    };
    await use(loginAsAnalystFn);
  },

  logout: async ({ page }, use) => {
    const logoutFn = async () => {
      // Try common logout patterns
      const logoutButton = page.getByRole('button', { name: /logout|sign out|log out/i });
      const logoutLink = page.getByRole('link', { name: /logout|sign out|log out/i });

      if (await logoutButton.isVisible()) {
        await logoutButton.click();
      } else if (await logoutLink.isVisible()) {
        await logoutLink.click();
      } else {
        // Try navigating to logout endpoint directly
        await page.goto('/logout');
      }

      // Wait for redirect to login page
      await page.waitForURL(/\/(login)?$/);
    };
    await use(logoutFn);
  },

  isLoggedIn: async ({ page }, use) => {
    const isLoggedInFn = async (): Promise<boolean> => {
      // Check for common logged-in indicators
      const currentUrl = page.url();
      if (currentUrl.includes('/login')) {
        return false;
      }

      // Check for logout button as indicator of logged-in state
      const logoutIndicator = page.getByRole('button', { name: /logout|sign out/i })
        .or(page.getByRole('link', { name: /logout|sign out/i }));

      try {
        await logoutIndicator.waitFor({ state: 'visible', timeout: 2000 });
        return true;
      } catch {
        return false;
      }
    };
    await use(isLoggedInFn);
  },
});

export { expect };

/**
 * Page object helpers for common UI patterns
 */
export class DashboardPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/dashboard');
    await this.page.waitForLoadState('networkidle');
  }

  async waitForLoad() {
    await this.page.waitForSelector('[data-testid="dashboard"]', { timeout: 10000 });
  }

  async getAgentCount(): Promise<number> {
    const countElement = this.page.locator('[data-testid="agent-count"]');
    const text = await countElement.textContent();
    return parseInt(text || '0', 10);
  }

  async getAlertCount(): Promise<number> {
    const countElement = this.page.locator('[data-testid="alert-count"]');
    const text = await countElement.textContent();
    return parseInt(text || '0', 10);
  }
}

export class AlertsPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/alerts');
    await this.page.waitForLoadState('networkidle');
  }

  async getAlerts() {
    return this.page.locator('[data-testid="alert-row"]').all();
  }

  async filterBySeverity(severity: 'critical' | 'high' | 'medium' | 'low') {
    await this.page.getByRole('combobox', { name: /severity/i }).selectOption(severity);
  }

  async searchAlerts(query: string) {
    await this.page.getByPlaceholder(/search/i).fill(query);
    await this.page.keyboard.press('Enter');
  }
}

export class AgentsPage {
  constructor(private page: Page) {}

  async goto() {
    await this.page.goto('/agents');
    await this.page.waitForLoadState('networkidle');
  }

  async getAgentRows() {
    return this.page.locator('[data-testid="agent-row"]').all();
  }

  async selectAgent(agentId: string) {
    await this.page.locator(`[data-testid="agent-${agentId}"]`).click();
  }

  async filterByStatus(status: 'online' | 'offline' | 'all') {
    await this.page.getByRole('combobox', { name: /status/i }).selectOption(status);
  }
}
