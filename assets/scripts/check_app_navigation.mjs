import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function findServerRoot() {
  let current = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

  while (current !== path.dirname(current)) {
    if (
      fs.existsSync(path.join(current, 'assets/src/layouts/MainLayout.tsx')) &&
      fs.existsSync(path.join(current, 'lib/tamandua_server_web/router.ex'))
    ) {
      return current;
    }

    const monorepoServer = path.join(current, 'apps/tamandua_server');
    if (
      fs.existsSync(path.join(monorepoServer, 'assets/src/layouts/MainLayout.tsx')) &&
      fs.existsSync(path.join(monorepoServer, 'lib/tamandua_server_web/router.ex'))
    ) {
      return monorepoServer;
    }

    current = path.dirname(current);
  }

  throw new Error('Could not locate tamandua_server root');
}

const serverRoot = findServerRoot();

function read(relativePath) {
  return fs.readFileSync(path.join(serverRoot, relativePath), 'utf8');
}

function unique(values) {
  return [...new Set(values)].sort();
}

function routeToRegex(route) {
  const escaped = route
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\:([A-Za-z0-9_]+)/g, '[^/]+')
    .replace(/\\\*path/g, '.*');
  return new RegExp(`^${escaped}$`);
}

const sourceFiles = [
  'assets/src/layouts/MainLayout.tsx',
  'assets/src/components/GlobalSearch.tsx',
];

const hrefs = sourceFiles.flatMap((file) => {
  const content = read(file);
  return [...content.matchAll(/href:\s*['"]([^'"]+)['"]/g)].map((match) => ({
    href: match[1],
    file,
  }));
});

const router = read('lib/tamandua_server_web/router.ex');
const appRoutes = unique(
  [...router.matchAll(/get\("([^"]+)",\s*InertiaController/g)]
    .map((match) => match[1])
    .filter((route) => route !== '/*path')
    .map((route) => (route === '/' ? '/app' : `/app${route}`))
);
const routePatterns = appRoutes.map(routeToRegex);

const missingRoutes = hrefs.filter(({ href }) => {
  if (!href.startsWith('/app')) return false;
  const normalized = href.replace(/[?#].*$/, '');
  return !routePatterns.some((pattern) => pattern.test(normalized));
});

const inertiaController = read('lib/tamandua_server_web/controllers/inertia_controller.ex');
const renderedPages = unique(
  [...inertiaController.matchAll(/render_inertia\(conn,\s*"([^"]+)"/g)].map((match) => match[1])
);

const missingPages = renderedPages.filter((page) => {
  const candidates = [
    `assets/src/pages/${page}.tsx`,
    `assets/src/pages/${page}.jsx`,
  ];
  return !candidates.some((candidate) => fs.existsSync(path.join(serverRoot, candidate)));
});

if (missingRoutes.length || missingPages.length) {
  if (missingRoutes.length) {
    console.error('Missing /app routes for static navigation hrefs:');
    for (const item of missingRoutes) {
      console.error(`- ${item.href} (${item.file})`);
    }
  }

  if (missingPages.length) {
    console.error('Missing Inertia page components:');
    for (const page of missingPages) {
      console.error(`- ${page}`);
    }
  }

  process.exit(1);
}

console.log(`Navigation OK: ${hrefs.length} hrefs, ${appRoutes.length} /app routes, ${renderedPages.length} Inertia pages.`);
