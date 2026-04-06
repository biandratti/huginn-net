/**
 * Fetches max_version from crates.io for each Huginn Net crate and writes
 * src/data/crate-versions.json for the remark plugin and for reference.
 */
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const outFile = join(root, 'src/data/crate-versions.json');

const CRATES = [
  'huginn-net',
  'huginn-net-tcp',
  'huginn-net-http',
  'huginn-net-tls',
  'huginn-net-db',
];

const USER_AGENT = 'huginn-net-docs-site (https://github.com/biandratti/huginn-net)';

async function fetchVersion(name) {
  const res = await fetch(`https://crates.io/api/v1/crates/${name}`, {
    headers: {
      'User-Agent': USER_AGENT,
      Accept: 'application/json',
    },
  });
  if (!res.ok) {
    throw new Error(`crates.io ${name}: HTTP ${res.status}`);
  }
  const data = await res.json();
  const v = data?.crate?.max_version;
  if (!v) {
    throw new Error(`crates.io ${name}: missing max_version`);
  }
  return v;
}

async function main() {
  const versions = {};
  for (const name of CRATES) {
    versions[name] = await fetchVersion(name);
    console.log(`${name}@${versions[name]}`);
  }

  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, `${JSON.stringify(versions, null, 2)}\n`, 'utf8');
  console.log(`Wrote ${outFile}`);
}

main().catch((err) => {
  if (existsSync(outFile)) {
    console.warn(`[fetch-crate-versions] ${err.message}`);
    console.warn(`Keeping existing ${outFile}`);
    process.exit(0);
  }
  console.error(err);
  process.exit(1);
});
