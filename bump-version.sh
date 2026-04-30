#!/usr/bin/env bash
set -euo pipefail

NEW=${1:-}
if [ -z "$NEW" ]; then
  echo "Usage: $0 <new-version>"
  exit 1
fi

OLD=$(grep '^version = ' Cargo.toml | grep -oP '[\d]+\.[\d]+\.[\d]+')
OLD_ESC=$(echo "$OLD" | sed 's/\./\\./g')

FILES=(
  Cargo.toml
  README.md
  huginn-net/README.md
  huginn-net-tls/README.md
  huginn-net-tcp/README.md
  huginn-net-http/README.md
)

echo "Bumping $OLD → $NEW"
for f in "${FILES[@]}"; do
  sed -i "s/$OLD_ESC/$NEW/g" "$f"
  echo "  $f"
done