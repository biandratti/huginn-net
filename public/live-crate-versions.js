// Fills {{crate}} placeholders in the docs from the public crates.io release.
// Longest name first so {{huginn-net}} does not match {{huginn-net-tcp}}.
const CRATES = [
  'huginn-net-tcp',
  'huginn-net-http',
  'huginn-net-tls',
  'huginn-net-db',
  'huginn-net',
];

let versionsPromise;

function loadVersions() {
  if (!versionsPromise) {
    versionsPromise = Promise.all(
      CRATES.map((name) =>
        fetch(`https://crates.io/api/v1/crates/${name}`)
          .then((response) => {
            if (!response.ok) throw new Error(`crates.io ${name}: HTTP ${response.status}`);
            return response.json();
          })
          .then((data) => {
            const version = data?.crate?.max_version;
            if (!version) throw new Error(`crates.io ${name}: missing max_version`);
            return [name, version];
          }),
      ),
    ).then((pairs) => Object.fromEntries(pairs));
  }
  return versionsPromise;
}

function fill(text, versions) {
  let value = text;
  for (const name of CRATES) {
    value = value.split(`{{${name}}}`).join(versions[name]);
  }
  return value;
}

function applyVersions(versions) {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);

  for (const node of nodes) {
    if (!node.nodeValue || !node.nodeValue.includes('{{')) continue;
    node.nodeValue = fill(node.nodeValue, versions);
  }

  // A highlighter can split {{crate}} across spans. Those lines still
  // contain the placeholder; replace the line text in that case.
  document.querySelectorAll('pre').forEach((pre) => {
    const lines = pre.querySelectorAll('.ec-line');
    const targets = lines.length > 0 ? lines : [pre];
    targets.forEach((line) => {
      const text = line.textContent ?? '';
      if (!text.includes('{{')) return;
      const next = fill(text, versions);
      if (next !== text) line.textContent = next;
    });
  });
}

function refresh() {
  loadVersions().then(applyVersions).catch(() => {});
}

document.addEventListener('astro:page-load', refresh);
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', refresh);
} else {
  refresh();
}
