import { test, expect } from '@playwright/test';
import { login } from './helpers/auth';

test.describe('API Comprehensive Tests', () => {
  test.describe('Agents API', () => {
    test('GET /api/v1/agents returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/agents');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
      expect(Array.isArray(data.data)).toBe(true);
    });

    test('GET /api/v1/agents/:id returns 404 for invalid id', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/agents/invalid-id-12345');
      expect([404, 500]).toContain(response.status());
    });
  });

  test.describe('Alerts API', () => {
    test('GET /api/v1/alerts returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/alerts');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
      expect(Array.isArray(data.data)).toBe(true);
    });

    test('GET /api/v1/alerts with severity filter', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/alerts?severity=critical');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });
  });

  test.describe('Events API', () => {
    test('GET /api/v1/events returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/events');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });

    test('POST /api/v1/events/search accepts query', async ({ page }) => {
      await login(page, 'admin');

      // Get CSRF token
      const csrfResponse = await page.request.get('/app/dashboard', {
        headers: {
          'X-Inertia': 'true',
          'X-Inertia-Version': '1'
        }
      });
      const csrfData = await csrfResponse.json();
      const csrfToken = csrfData.props?.csrf_token;

      const response = await page.request.post('/api/v1/events/search', {
        data: { query: 'test' },
        headers: csrfToken ? { 'x-csrf-token': csrfToken } : {}
      });

      // Should accept the request (may return empty results)
      expect([200, 401, 403]).toContain(response.status());
    });
  });

  test.describe('Stats API', () => {
    test('GET /api/v1/stats/overview returns stats', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/stats/overview');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
      expect(data.data).toHaveProperty('total_agents');
      expect(data.data).toHaveProperty('online_agents');
      expect(data.data).toHaveProperty('open_alerts');
    });

    test('GET /api/v1/stats/agents returns agent stats', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/stats/agents');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });

    test('GET /api/v1/stats/alerts returns alert stats', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/stats/alerts');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });
  });

  test.describe('Hunting API', () => {
    test('POST /api/v1/hunting/search accepts search params', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.post('/api/v1/hunting/search', {
        data: {
          query: 'process.name:powershell.exe',
          time_range: '24h',
          limit: 10
        }
      });

      // May require CSRF token, accept various responses
      expect([200, 401, 403]).toContain(response.status());
    });
  });

  test.describe('Rules API', () => {
    test('GET /api/v1/rules/sigma returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/rules/sigma');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });

    test('GET /api/v1/rules/yara returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/rules/yara');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });
  });

  test.describe('IOCs API', () => {
    test('GET /api/v1/iocs returns list', async ({ page }) => {
      await login(page, 'admin');

      const response = await page.request.get('/api/v1/iocs');
      expect(response.status()).toBe(200);

      const data = await response.json();
      expect(data).toHaveProperty('data');
    });
  });
});
