import { test, expect, type Page, type Route } from '@playwright/test';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { login, waitForInertiaNavigation } from './helpers/auth';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const staticAssetsDir = path.resolve(__dirname, '../../priv/static/assets');
const manifestPath = path.join(staticAssetsDir, 'manifest.json');

const useRealServer = process.env.E2E_HUNT_REAL_SERVER === '1';

test.use({ storageState: undefined });

test.describe('Threat Hunt Page', () => {
  test.beforeEach(async ({ page }) => {
    if (useRealServer) {
      await login(page, 'admin');
      await page.goto('/app/hunt');
      await waitForInertiaNavigation(page);
      return;
    }

    // Fixture mode is the default for validation/history coverage because it
    // keeps the suite independent from local auth, database seed state, and API uptime.
    // Run npm run build first so the spec can serve the real compiled Inertia app.
    test.skip(!fs.existsSync(manifestPath), 'Hunt fixture requires built assets; run npm run build or set E2E_HUNT_REAL_SERVER=1.');

    await serveBuiltHuntPage(page);
    await page.goto('/app/hunt', { waitUntil: 'domcontentloaded' });
    await page.getByTestId('hunt-query-input').waitFor({ state: 'visible' });
  });

  test('hunt page loads correctly', async ({ page }) => {
    await expect(page).toHaveTitle(/Threat Hunt/);
    await expect(page.getByRole('heading', { name: 'Query Builder' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /Quick Queries|Saved Queries/ })).toBeVisible();
  });

  test('query builder elements are present', async ({ page }) => {
    const textarea = page.getByTestId('hunt-query-input');
    await expect(textarea).toBeVisible();
    await expect(textarea).toHaveAttribute('placeholder', /Enter query/);

    await expect(page.getByText('Time Range:')).toBeVisible();
    await expect(page.getByTestId('hunt-time-range-select')).toHaveText(/24h/);
    await expect(page.getByTestId('hunt-run-query-button')).toBeVisible();
  });

  test('run query button is disabled when query is empty', async ({ page }) => {
    await expect(page.getByTestId('hunt-run-query-button')).toBeDisabled();
  });

  test('run query button is enabled when query has content', async ({ page }) => {
    await page.getByTestId('hunt-query-input').fill('process.name:powershell.exe');
    await expect(page.getByTestId('hunt-run-query-button')).toBeEnabled();
  });

  test('shows actionable validation for adjacent conditions without connector', async ({ page }) => {
    await page.getByTestId('hunt-query-input').fill('process.name:cmd.exe network.remote_port:443');
    await page.getByTestId('hunt-run-query-button').click();

    await expect(page.getByText('Missing connector before "network.remote_port:443"', { exact: false })).toBeVisible();
    await expect(page.getByText('Query has validation errors. Review them before running.')).toBeVisible();
  });

  test('query shortcut populates the editor with a valid query', async ({ page }) => {
    await page.getByTestId('hunt-query-shortcut').first().click();

    await expect(page.getByTestId('hunt-query-input')).not.toHaveValue('');
    await expect(page.getByText('Query syntax is valid')).toBeVisible();
  });

  test('time range can be changed', async ({ page }) => {
    await page.getByTestId('hunt-time-range-select').click();
    await page.getByText('Last 7 days').click();

    await expect(page.getByTestId('hunt-time-range-select')).toHaveText(/7d/);
  });

  test('save button is visible', async ({ page }) => {
    await expect(page.getByTestId('hunt-save-query-button')).toBeVisible();
  });

  test('history panel loads query history from the API contract', async ({ page }) => {
    await page.getByTestId('hunt-history-button').click();

    await expect(page.getByText('Query History')).toBeVisible();
    await expect(page.getByRole('button', { name: /process\.name:cmd\.exe/ })).toBeVisible();
  });

  test('running a query shows loading state without crashing', async ({ page }) => {
    await page.getByTestId('hunt-query-input').fill('process.name:test.exe');
    await page.getByTestId('hunt-run-query-button').click();

    await expect(page).toHaveURL(/\/app\/hunt/);
    await expect(page.getByText(/0 results in 24h|No results yet/)).toBeVisible();
  });
});

async function serveBuiltHuntPage(page: Page) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
    'src/main.tsx': { file: string; css?: string[] };
  };
  const entry = manifest['src/main.tsx'];

  await page.route('/app/hunt', route => {
    route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: inertiaHtml(entry.file, entry.css ?? []),
    });
  });

  await page.route('/images/**', route => route.fulfill({ status: 204, body: '' }));
  await page.route('/favicon.ico', route => route.fulfill({ status: 204, body: '' }));
  await page.route('/assets/**', route => fulfillStaticAsset(route));
  await page.route('/api/v1/hunting/schema', route => route.fulfill(jsonResponse(huntSchemaFixture)));
  await page.route('/api/v1/hunting/templates', route => route.fulfill(jsonResponse({
    data: { templates: [], categories: ['Execution'], source: 'static', static: true, degraded: false },
  })));
  await page.route('/api/v1/queries?limit=50', route => route.fulfill(jsonResponse({ data: [] })));
  await page.route('/api/v1/queries/history?unique=true&limit=20', route => route.fulfill(jsonResponse({
    data: [{
      id: 'history-1',
      query: 'process.name:cmd.exe',
      type: 'hunt',
      result_count: 3,
      execution_time_ms: 12,
      executed_at: '2026-07-13T12:00:00Z',
    }],
  })));
  await page.route('/api/v1/queries/history', route => route.fulfill(jsonResponse({ data: { id: 'history-new' } })));
  await page.route('/api/v1/hunting/tql-schema', route => route.fulfill(jsonResponse({ data: tqlSchemaFixture })));
  await page.route('/api/v1/hunting/search', route => route.fulfill(jsonResponse({
    data: [],
    meta: { total: 0, time_range: '24h', execution_time_ms: 1 },
  })));
}

function inertiaHtml(entryFile: string, cssFiles: string[]) {
  const page = {
    component: 'Hunt',
    props: {
      savedQueries: [],
      current_tenant: null,
      available_tenants: [],
    },
    url: '/app/hunt',
    version: null,
  };

  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="csrf-token" content="hunt-fixture-csrf">
    <title>Threat Hunt - Tamandua EDR</title>
    ${cssFiles.map(file => `<link rel="stylesheet" href="/assets/${file}">`).join('\n    ')}
  </head>
  <body>
    <div id="app" data-page='${JSON.stringify(page)}'></div>
    <script type="module" src="/assets/${entryFile}"></script>
  </body>
</html>`;
}

function fulfillStaticAsset(route: Route) {
  const url = new URL(route.request().url());
  const relativePath = decodeURIComponent(url.pathname.replace(/^\/assets\//, ''));
  const assetPath = path.resolve(staticAssetsDir, relativePath);

  if (!assetPath.startsWith(staticAssetsDir) || !fs.existsSync(assetPath)) {
    return route.fulfill({ status: 404, body: 'Not found' });
  }

  return route.fulfill({
    status: 200,
    contentType: contentTypeFor(assetPath),
    body: fs.readFileSync(assetPath),
  });
}

function contentTypeFor(filePath: string) {
  if (filePath.endsWith('.js')) return 'text/javascript';
  if (filePath.endsWith('.css')) return 'text/css';
  if (filePath.endsWith('.svg')) return 'image/svg+xml';
  if (filePath.endsWith('.woff2')) return 'font/woff2';
  return 'application/octet-stream';
}

function jsonResponse(body: unknown) {
  return {
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(body),
  };
}

const huntSchemaFixture = {
  data: {
    fields: {
      process: [
        { field: 'process.name', label: 'Process Name', type: 'string' },
        { field: 'process.user', label: 'User', type: 'string' },
      ],
      network: [
        { field: 'network.remote_port', label: 'Remote Port', type: 'number' },
      ],
    },
    operators: [
      { value: ':', label: 'equals', symbol: '=', types: ['string', 'number'] },
    ],
    categories: ['Execution'],
  },
};

const tqlSchemaFixture = {
  version: 'fixture',
  name: 'TQL fixture',
  description: 'Minimal Hunt e2e fixture',
  table_sources: ['events'],
  operators: {},
  aggregation_functions: [],
  scalar_functions: [],
  keywords: [],
  field_mappings: {},
  syntax: {
    basic_structure: 'events | where field == value',
    operators: [],
    comparison_operators: [],
    logical_operators: [],
  },
  examples: [],
};
