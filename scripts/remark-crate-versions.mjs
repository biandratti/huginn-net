/**
 * Replaces {{v:crate-name}} in markdown/mdx with versions from crate-versions.json.
 */
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const versionsPath = join(__dirname, '..', 'src', 'data', 'crate-versions.json');

function loadVersions() {
  if (!existsSync(versionsPath)) {
    console.warn(
      `[remark-crate-versions] Missing ${versionsPath}; run: node scripts/fetch-crate-versions.mjs`,
    );
    return {};
  }
  try {
    return JSON.parse(readFileSync(versionsPath, 'utf8'));
  } catch {
    return {};
  }
}

function replaceInString(str, versions) {
  if (!str || typeof str !== 'string') return str;
  let out = str;
  for (const [crate, ver] of Object.entries(versions)) {
    out = out.split(`{{v:${crate}}}`).join(ver);
  }
  return out;
}

function visitTree(node, versions) {
  if (!node || typeof node !== 'object') return;

  if (node.type === 'code' && typeof node.value === 'string') {
    node.value = replaceInString(node.value, versions);
  }
  if (node.type === 'inlineCode' && typeof node.value === 'string') {
    node.value = replaceInString(node.value, versions);
  }
  if (node.type === 'text' && typeof node.value === 'string') {
    node.value = replaceInString(node.value, versions);
  }

  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      visitTree(child, versions);
    }
  }
}

export default function remarkCrateVersions() {
  const versions = loadVersions();

  return (tree) => {
    visitTree(tree, versions);
  };
}
